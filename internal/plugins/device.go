// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Exec plugins on devices (#223): the operator uploads a plugin's program
// and manifest to the hub, for each platform; the hub hands them to the
// agents whose capability ceiling allows the plugin, and an agent runs one
// of its commands on a process of its own (RunOnce).

// MaxProgramSize caps a device plugin's program: the hub refuses a larger
// upload and the agent a larger download.
const MaxProgramSize = 64 << 20

// BlobPath is where an agent fetches a device plugin's program from the hub
// it streams to, followed by the program's SHA-256 in hex, with its client
// certificate.
const BlobPath = "/hearth.agent.v1.Plugins/blobs/"

// ErrPinMismatch is a program whose SHA-256 is not the one pinned.
var ErrPinMismatch = errors.New("the program's SHA-256 is not the one pinned")

// Release is what a device runs of a plugin: its program, by SHA-256, and
// the parts of its manifest that decide what runs and at what class.
type Release struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	SHA256       string        `json:"sha256"`
	Args         []string      `json:"args"`
	Capabilities []string      `json:"capabilities"`
	Commands     []CommandSpec `json:"commands"`
}

// Digest pins r: the SHA-256, in hex, of its program's SHA-256 and of the
// SHA-256 of its manifest in canonical JSON. A new program, or the same one
// with other args or another class for a command, is another release.
func (r Release) Digest() string {
	m := r
	m.SHA256 = ""
	if m.Args == nil {
		m.Args = []string{}
	}
	if m.Capabilities == nil {
		m.Capabilities = []string{}
	}
	if m.Commands == nil {
		m.Commands = []CommandSpec{}
	}
	b, _ := json.Marshal(m) // plain strings and slices: it cannot fail
	mh := sha256.Sum256(b)
	d := sha256.Sum256([]byte(r.SHA256 + "\n" + hex.EncodeToString(mh[:])))
	return hex.EncodeToString(d[:])
}

// ReleaseOf is the release b offers a device.
func ReleaseOf(b *agentv1.PluginBinary) Release {
	r := Release{
		Name: b.GetName(), Version: b.GetVersion(), SHA256: b.GetSha256(),
		Args: slices.Clone(b.GetArgs()), Capabilities: slices.Clone(b.GetCapabilities()),
	}
	for _, c := range b.GetCommands() {
		r.Commands = append(r.Commands, CommandSpec{Name: c.GetName(), Class: policy.Class(c.GetClass()), Description: c.GetDescription()})
	}
	return r
}

// ValidSHA256 reports whether s is a SHA-256 in lower-case hex.
func ValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// ParseManifest reads a manifest uploaded for devices: as LoadManifest
// does, without a file of its own. Its command is ignored on a device, where
// the uploaded program runs; it may set no env, which would reach the
// store and every hub of a cluster.
func ParseManifest(b []byte) (Manifest, error) {
	if len(b) > maxManifest {
		return Manifest{}, fmt.Errorf("plugin manifest: larger than %d bytes", maxManifest)
	}
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest: %w", err)
	}
	if m.Command == "" {
		m.Command = m.Name // ignored on a device; Validate wants one
	}
	if m.Runtime != "" && m.Runtime != RuntimeExec {
		return Manifest{}, fmt.Errorf("plugin manifest: runtime %q: a device plugin is an exec plugin (WASM plugins run on the hub only)", m.Runtime)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest: %w", err)
	}
	if len(m.Env) > 0 {
		return Manifest{}, errors.New("plugin manifest: env is not allowed for a device plugin: it would be stored on every hub " +
			"and sent to every device the plugin is allowed on; keep settings in a file on the device")
	}
	return m, nil
}

// CommandClass is the class m declares for command, and whether it declares
// it.
func (m Manifest) CommandClass(command string) (policy.Class, bool) {
	spec, ok := m.command(command)
	if !ok {
		return "", false
	}
	return spec.Class, true
}

// RunOnce runs one command of the plugin m on a process of its own, as an
// agent does: it checks the program and the directories above it as a
// start on the hub does, and that its SHA-256 is pin, starts it without a
// shell in a clean environment and a process group of its own, waits for its
// hello, sends the command and waits for the result, then kills the process
// group. m.Command is the program's path. The command must be one m declares;
// the caller decided on it.
func RunOnce(ctx context.Context, m Manifest, pin string, req CommandRequest, o Options) (CommandResult, error) {
	if err := m.Validate(); err != nil {
		return CommandResult{}, fmt.Errorf("plugin %s: %w", m.Name, err)
	}
	if m.IsWasm() {
		return CommandResult{}, fmt.Errorf("plugin %s: a device plugin is an exec plugin (WASM plugins run on the hub only)", m.Name)
	}
	if err := checkRequest(req); err != nil {
		return CommandResult{}, err
	}
	if _, ok := m.command(req.Command); !ok {
		return CommandResult{}, fmt.Errorf("plugin %s declares no command %q: %w", m.Name, req.Command, policy.ErrDenied)
	}
	p := &plugin{m: m, o: o.withDefaults(), log: slog.New(slog.DiscardHandler), now: time.Now, state: StateStopped}
	path, err := p.resolve()
	if err != nil {
		return CommandResult{}, err
	}
	// Checked before every start: what runs is what is on disk now.
	before, err := os.Stat(path)
	if err != nil {
		return CommandResult{}, fmt.Errorf("plugin %s: %w", m.Name, err)
	}
	path, digest, err := p.trustedProgram(path)
	if err != nil {
		return CommandResult{}, err
	}
	if digest != pin {
		return CommandResult{}, fmt.Errorf("plugin %s: %s is %s: %w", m.Name, path, digest, ErrPinMismatch)
	}
	pctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var pipes []*os.File
	for range 3 {
		r, w, err := os.Pipe()
		if err != nil {
			for _, f := range pipes {
				_ = f.Close()
			}
			return CommandResult{}, fmt.Errorf("plugin %s: pipe: %w", m.Name, err)
		}
		pipes = append(pipes, r, w)
	}
	inR, inW, outR, outW, errR, errW := pipes[0], pipes[1], pipes[2], pipes[3], pipes[4], pipes[5]
	// The program is started by path: it must still be the file hashed.
	if after, err := os.Stat(path); err != nil || !os.SameFile(before, after) ||
		!after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		for _, f := range pipes {
			_ = f.Close()
		}
		return CommandResult{}, fmt.Errorf("plugin %s: %s changed while it was checked: %w", m.Name, path, ErrPinMismatch)
	}
	cmd := exec.Command(path, m.Args...)
	cmd.Dir, cmd.Env = m.Dir, p.env()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	inOwnGroup(cmd)
	err = cmd.Start()
	_, _, _ = inR.Close(), outW.Close(), errW.Close()
	if err != nil {
		_, _, _ = inW.Close(), outR.Close(), errR.Close()
		return CommandResult{}, fmt.Errorf("start plugin %s: %w", m.Name, err)
	}
	pr := &proc{
		send: make(chan []byte, 8), dead: pctx.Done(), cancel: cancel,
		pending: map[string]pendingReply{}, slots: make(chan struct{}, 1),
	}
	hello := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		err := cmd.Wait()
		if err == nil {
			err = errors.New("exited")
		}
		cancel(fmt.Errorf("plugin process: %w", err))
	})
	wg.Go(func() { cancel(p.readLoop(pctx, pr, outR, hello)) })
	wg.Go(func() { p.stderrLoop(errR) })
	wg.Go(func() { cancel(writeLoop(pctx, pr, inW)) })
	defer func() {
		killTree(cmd.Process)
		_, _, _ = inW.Close(), outR.Close(), errR.Close()
		wg.Wait()
	}()

	pr.send <- line(message{Type: typeHello, Protocol: ProtocolVersion})
	t := time.NewTimer(p.o.StartTimeout)
	defer t.Stop()
	select {
	case <-hello:
	case <-pctx.Done():
		return CommandResult{}, fmt.Errorf("plugin %s: %w", m.Name, context.Cause(pctx))
	case <-t.C:
		return CommandResult{}, fmt.Errorf("plugin %s: no hello within %s: %w", m.Name, p.o.StartTimeout, ErrUnavailable)
	}
	p.mu.Lock()
	p.proc = pr
	p.mu.Unlock()
	res, err := p.command(ctx, req)
	if errors.Is(err, ErrUnavailable) {
		if cause := context.Cause(pctx); cause != nil {
			err = fmt.Errorf("%w: %w", err, cause)
		}
	}
	return res, err
}
