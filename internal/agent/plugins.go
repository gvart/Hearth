// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Exec plugins on this device (#223). The hub sends a PluginConfig: the
// plugins it has for the device, for every platform. The agent installs
// those of its own platform that its effective ceiling allows: it fetches
// each program from the hub with its client certificate, at most
// plugins.MaxProgramSize, streamed to disk, and keeps it, 0700, under
// <data>/plugins/<name>/<sha256> only once its SHA-256 is the one pinned.
// It reports what it installed in a PluginStatus.
//
// A PluginCommand starts the plugin on a process of its own, runs the
// command and stops it (plugins.RunOnce), which checks the program's
// SHA-256 again before the start. The agent refuses a plugin its ceiling
// does not allow, a command the installed manifest does not declare, and
// one whose class, from that manifest, is above the class its ceiling
// allows for the plugin, whatever the hub decided.

// PluginsDir is the directory of the data dir that holds the plugins.
const PluginsDir = "plugins"

const (
	// defaultPluginTimeout is a command's timeout when the hub sets none,
	// and maxPluginTimeout the longest it may set.
	defaultPluginTimeout = 30 * time.Second
	maxPluginTimeout     = 5 * time.Minute
)

// PluginGrant allows one exec plugin, up to a class of command.
type PluginGrant struct {
	Name  string
	Class policy.Class
}

// ParsePluginGrant parses an --allow-plugin entry: NAME or NAME:CLASS, with
// CLASS read, safe or dangerous; NAME alone allows read commands only.
func ParsePluginGrant(entry string) (PluginGrant, error) {
	name, class, ok := strings.Cut(entry, ":")
	g := PluginGrant{Name: name, Class: policy.Read}
	if ok {
		g.Class = policy.Class(class)
	}
	if err := policy.CheckPluginGrants([]*agentv1.PluginGrant{{Name: g.Name, MaxClass: string(g.Class)}}); err != nil {
		return PluginGrant{}, err
	}
	return g, nil
}

// grantsProto is gs as sent.
func grantsProto(gs []PluginGrant) []*agentv1.PluginGrant {
	if len(gs) == 0 {
		return nil
	}
	out := make([]*agentv1.PluginGrant, 0, len(gs))
	for _, g := range gs {
		out = append(out, &agentv1.PluginGrant{Name: g.Name, MaxClass: string(g.Class)})
	}
	return out
}

// grantsOf is gs as the agent holds them: sorted by name.
func grantsOf(gs []*agentv1.PluginGrant) []PluginGrant {
	var out []PluginGrant
	for _, g := range gs {
		out = append(out, PluginGrant{Name: g.GetName(), Class: policy.Class(g.GetMaxClass())})
	}
	return sortGrants(out)
}

// unionGrants is what a or b allows: each plugin of either, at the higher of
// its classes.
func unionGrants(a, b []PluginGrant) []PluginGrant {
	out := slices.Clone(a)
	for _, g := range b {
		i := slices.IndexFunc(out, func(o PluginGrant) bool { return o.Name == g.Name })
		switch {
		case i < 0:
			out = append(out, g)
		case policy.ClassAbove(g.Class, out[i].Class):
			out[i].Class = g.Class
		}
	}
	return sortGrants(out)
}

func sortGrants(gs []PluginGrant) []PluginGrant {
	slices.SortFunc(gs, func(a, b PluginGrant) int { return strings.Compare(a.Name, b.Name) })
	return gs
}

// pluginHost installs and runs the device's plugins.
type pluginHost struct {
	dir     string
	log     *slog.Logger
	ceiling func() Ceiling
	// opts bound a plugin's process; tests shorten them.
	opts plugins.Options

	// gen numbers the configs received; a sync of an older one is
	// skipped. syncMu runs one sync at a time.
	gen    atomic.Uint64
	syncMu sync.Mutex

	mu        sync.Mutex
	installed map[string]installedPlugin
}

// installedPlugin is a plugin whose program is on disk, checked.
type installedPlugin struct {
	sha256   string
	version  string
	manifest plugins.Manifest
}

func newPluginHost(dataDir string, log *slog.Logger, ceiling func() Ceiling) *pluginHost {
	return &pluginHost{dir: filepath.Join(dataDir, PluginsDir), log: log, ceiling: ceiling, installed: map[string]installedPlugin{}}
}

// next numbers a config just received.
func (h *pluginHost) next() uint64 { return h.gen.Add(1) }

// sync installs the plugins of cfg, the gen-th config, fetching what is
// missing from hub with client, and removes the rest. It returns their
// state, or nil when a newer config came in meanwhile.
func (h *pluginHost) sync(ctx context.Context, client *http.Client, hub string, cfg *agentv1.PluginConfig, gen uint64) *agentv1.PluginStatus {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	if gen != h.gen.Load() {
		return nil
	}
	st := &agentv1.PluginStatus{Os: runtime.GOOS, Arch: runtime.GOARCH}
	var names []string
	mine := map[string]*agentv1.PluginBinary{}
	for _, b := range cfg.GetPlugins() {
		if !slices.Contains(names, b.GetName()) {
			names = append(names, b.GetName())
		}
		if b.GetOs() == runtime.GOOS && b.GetArch() == runtime.GOARCH && mine[b.GetName()] == nil {
			mine[b.GetName()] = b
		}
	}
	slices.Sort(names)
	c := h.ceiling().proto()
	next := map[string]installedPlugin{}
	for _, name := range names {
		state := &agentv1.PluginState{Name: name}
		st.Plugins = append(st.Plugins, state)
		b := mine[name]
		if b == nil {
			state.Error = fmt.Sprintf("no program uploaded for this device's platform, %s/%s", runtime.GOOS, runtime.GOARCH)
			continue
		}
		state.Version = b.GetVersion()
		inst, err := h.install(ctx, client, hub, c, b)
		if err != nil {
			h.log.WarnContext(ctx, "plugin not installed", "plugin", name, "err", err)
			state.Error = err.Error()
			continue
		}
		state.Sha256 = inst.sha256
		next[name] = inst
	}
	h.mu.Lock()
	h.installed = next
	h.mu.Unlock()
	h.prune(ctx, next)
	return st
}

// install checks b and makes sure its program is on disk.
func (h *pluginHost) install(ctx context.Context, client *http.Client, hub string, c *agentv1.Ceiling, b *agentv1.PluginBinary) (installedPlugin, error) {
	switch {
	case !policy.ValidPluginName(b.GetName()):
		return installedPlugin{}, fmt.Errorf("invalid plugin name %.64q", b.GetName())
	case !plugins.ValidSHA256(b.GetSha256()):
		return installedPlugin{}, errors.New("invalid SHA-256")
	case b.GetOs() != runtime.GOOS || b.GetArch() != runtime.GOARCH:
		return installedPlugin{}, fmt.Errorf("the program is for %s/%s, not this device's %s/%s",
			b.GetOs(), b.GetArch(), runtime.GOOS, runtime.GOARCH)
	case b.GetSize() > plugins.MaxProgramSize:
		return installedPlugin{}, fmt.Errorf("the program is larger than %d MiB", plugins.MaxProgramSize>>20)
	}
	if err := policy.PluginWithinCeiling(c, b.GetName(), ""); err != nil {
		return installedPlugin{}, err
	}
	dir := filepath.Join(h.dir, b.GetName())
	path := filepath.Join(dir, b.GetSha256())
	m := plugins.Manifest{
		Protocol: plugins.ProtocolVersion, Name: b.GetName(), Version: b.GetVersion(), Command: path, Dir: dir,
		Args: slices.Clone(b.GetArgs()), Capabilities: slices.Clone(b.GetCapabilities()),
	}
	for _, c := range b.GetCommands() {
		m.Commands = append(m.Commands, plugins.CommandSpec{Name: c.GetName(), Class: policy.Class(c.GetClass()), Description: c.GetDescription()})
	}
	if err := m.Validate(); err != nil {
		return installedPlugin{}, fmt.Errorf("manifest: %w", err)
	}
	for _, d := range []string{h.dir, dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return installedPlugin{}, err
		}
		if err := os.Chmod(d, 0o700); err != nil { //nolint:gosec // a directory needs its search bit
			return installedPlugin{}, err
		}
	}
	if digest, err := fileSHA256(path); err != nil || digest != b.GetSha256() {
		if err := h.download(ctx, client, hub, b.GetSha256(), path); err != nil {
			return installedPlugin{}, err
		}
		h.log.InfoContext(ctx, "plugin installed", "plugin", b.GetName(), "version", b.GetVersion(), "sha256", b.GetSha256())
	}
	return installedPlugin{sha256: b.GetSha256(), version: b.GetVersion(), manifest: m}, nil
}

// download fetches the program of SHA-256 sum from hub into path: streamed
// to a temporary file of the same directory, at most
// plugins.MaxProgramSize, made executable and renamed into place only once
// its SHA-256 is sum.
func (h *pluginHost) download(ctx context.Context, client *http.Client, hub, sum, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(hub, "/")+plugins.BlobPath+sum, nil)
	if err != nil {
		return fmt.Errorf("fetch the program: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch the program: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("fetch the program: hub answered %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if resp.ContentLength > plugins.MaxProgramSize {
		return fmt.Errorf("fetch the program: larger than %d MiB", plugins.MaxProgramSize>>20)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return fmt.Errorf("fetch the program: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(resp.Body, plugins.MaxProgramSize+1))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return fmt.Errorf("fetch the program: %w", err)
	case n > plugins.MaxProgramSize:
		return fmt.Errorf("fetch the program: larger than %d MiB", plugins.MaxProgramSize>>20)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != sum {
		return fmt.Errorf("fetch the program: its SHA-256 is %s, not the pinned %s: %w", got, sum, plugins.ErrPinMismatch)
	}
	if err := os.Chmod(tmp.Name(), 0o700); err != nil { //nolint:gosec // the plugin's program, the agent's user's only
		return fmt.Errorf("fetch the program: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("fetch the program: %w", err)
	}
	return nil
}

// prune removes the plugins and programs not in keep.
func (h *pluginHost) prune(ctx context.Context, keep map[string]installedPlugin) {
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		inst, ok := keep[e.Name()]
		if !ok {
			if err := os.RemoveAll(filepath.Join(h.dir, e.Name())); err != nil {
				h.log.WarnContext(ctx, "remove a plugin", "plugin", e.Name(), "err", err)
			}
			continue
		}
		files, err := os.ReadDir(filepath.Join(h.dir, e.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.Name() != inst.sha256 && (len(f.Name()) == 64 || strings.HasPrefix(f.Name(), ".download-")) {
				_ = os.Remove(filepath.Join(h.dir, e.Name(), f.Name()))
			}
		}
	}
}

// fileSHA256 is the SHA-256 of the file at path, in hex.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// command runs req, within the effective ceiling.
func (h *pluginHost) command(ctx context.Context, req *agentv1.PluginCommand) *agentv1.PluginResult {
	res := &agentv1.PluginResult{Id: req.GetId()}
	deny := func(err error) *agentv1.PluginResult {
		res.Denied, res.Error = true, err.Error()
		return res
	}
	if !policy.ValidPluginName(req.GetPlugin()) || !plugins.ValidSHA256(req.GetSha256()) {
		return deny(errors.New("invalid plugin name or SHA-256"))
	}
	h.mu.Lock()
	inst, ok := h.installed[req.GetPlugin()]
	h.mu.Unlock()
	if !ok {
		return deny(fmt.Errorf("plugin %s is not installed on this device", req.GetPlugin()))
	}
	if inst.sha256 != req.GetSha256() {
		return deny(fmt.Errorf("plugin %s: the hub asked for program %.12s, this device has %.12s; it syncs at the next heartbeat",
			req.GetPlugin(), req.GetSha256(), inst.sha256))
	}
	// The class is the installed manifest's, never one the request names.
	class, declared := inst.manifest.CommandClass(req.GetCommand())
	if !declared {
		return deny(fmt.Errorf("plugin %s declares no command %.64q", req.GetPlugin(), req.GetCommand()))
	}
	if err := policy.PluginWithinCeiling(h.ceiling().proto(), req.GetPlugin(), class); err != nil {
		return deny(err)
	}
	creq := plugins.CommandRequest{Command: req.GetCommand(), Device: req.GetDevice()}
	if req.GetArgsJson() != "" {
		creq.Args = json.RawMessage(req.GetArgsJson())
	}
	o := h.opts
	o.CommandTimeout = defaultPluginTimeout
	if d := req.GetTimeout().AsDuration(); req.GetTimeout() != nil && d > 0 {
		o.CommandTimeout = min(d, maxPluginTimeout)
	}
	out, err := plugins.RunOnce(ctx, inst.manifest, inst.sha256, creq, o)
	switch {
	case errors.Is(err, policy.ErrDenied), errors.Is(err, plugins.ErrBadRequest), errors.Is(err, plugins.ErrPinMismatch):
		return deny(err)
	case err != nil:
		res.Error = err.Error()
		return res
	}
	res.Ok, res.Output = true, out.Output
	return res
}

// handlePlugin takes a PluginRequest from hub: a config is installed, and a
// command run, on a goroutine of execs, and the answer goes to reply.
func (r *runner) handlePlugin(ctx context.Context, hub string, req *agentv1.PluginRequest, execs *sync.WaitGroup, reply func(*agentv1.AgentMessage)) {
	if r.plugins == nil { // a runner a test made
		return
	}
	switch op := req.GetOp().(type) {
	case *agentv1.PluginRequest_Config:
		gen, client := r.plugins.next(), r.httpClient
		execs.Go(func() {
			if st := r.plugins.sync(ctx, client, hub, op.Config, gen); st != nil {
				reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_PluginEvent{PluginEvent: &agentv1.PluginEvent{
					Event: &agentv1.PluginEvent_Status{Status: st},
				}}})
			}
		})
	case *agentv1.PluginRequest_Command:
		cmd := op.Command
		execs.Go(func() {
			res := r.plugins.command(ctx, cmd)
			// Never log the arguments: they may carry secrets.
			r.log.InfoContext(ctx, "plugin command", "id", cmd.GetId(), "plugin", cmd.GetPlugin(), "command", cmd.GetCommand(),
				"denied", res.GetDenied(), "ok", res.GetOk())
			reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_PluginEvent{PluginEvent: &agentv1.PluginEvent{
				Event: &agentv1.PluginEvent_Result{Result: res},
			}}})
		})
	}
}
