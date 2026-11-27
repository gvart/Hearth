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

	"google.golang.org/protobuf/proto"

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
// A ceiling allows a release of a plugin: its digest
// (plugins.Release.Digest) binds the program and the manifest that says
// what runs and at what class. A grant the hub sets always pins one; an
// --allow-plugin flag without @DIGEST pins the first release the agent
// installs (trust on first use), in <data>/plugin-pins.json, until the flag
// changes. A new upload under the same name is another release: the agent
// keeps running the one it has until the ceiling allows the new one.
//
// A PluginCommand starts the plugin on a process of its own, runs the
// command and stops it (plugins.RunOnce), which checks the program's
// SHA-256 again before the start. The agent refuses a release its ceiling
// does not allow, a command the installed manifest does not declare, and
// one whose class, from that manifest, is above the class its ceiling
// allows for the release, whatever the hub decided. Device plugins are not
// supported on Windows yet: there the data dir has no ACL of the agent's
// own, and another local user could swap a program between its check and
// its start.

// PluginsDir is the directory of the data dir that holds the plugins.
const PluginsDir = "plugins"

// PluginPinsFile is the file of the data dir that holds the releases the
// agent pinned on first use.
const PluginPinsFile = "plugin-pins.json"

const (
	// defaultPluginTimeout is a command's timeout when the hub sets none,
	// and maxPluginTimeout the longest it may set.
	defaultPluginTimeout = 30 * time.Second
	maxPluginTimeout     = 5 * time.Minute
	// maxPluginCommands is how many plugin commands run at once; more are
	// refused.
	maxPluginCommands = 4
	// maxPluginsDisk caps the programs the agent keeps, all plugins
	// together.
	maxPluginsDisk = 512 << 20
)

// PluginGrant allows one exec plugin, up to a class of command: the release
// Digest, or, with none, the first release the agent installs.
type PluginGrant struct {
	Name   string
	Class  policy.Class
	Digest string
}

// ParsePluginGrant parses an --allow-plugin entry: NAME[:CLASS][@DIGEST],
// with CLASS read, safe or dangerous; NAME alone allows read commands only.
// Without DIGEST, the agent pins the first release it installs.
func ParsePluginGrant(entry string) (PluginGrant, error) {
	rest, digest, _ := strings.Cut(entry, "@")
	name, class, ok := strings.Cut(rest, ":")
	g := PluginGrant{Name: name, Class: policy.Read, Digest: digest}
	if ok {
		g.Class = policy.Class(class)
	}
	if strings.Contains(entry, "@") && digest == "" {
		return PluginGrant{}, fmt.Errorf("plugin entry %s: empty digest after @", name)
	}
	if err := policy.CheckPluginGrants(grantsProto([]PluginGrant{g})); err != nil {
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
		out = append(out, &agentv1.PluginGrant{Name: g.Name, MaxClass: string(g.Class), Digest: g.Digest})
	}
	return out
}

// grantsOf is gs as the agent holds them: sorted by name and digest.
func grantsOf(gs []*agentv1.PluginGrant) []PluginGrant {
	var out []PluginGrant
	for _, g := range gs {
		out = append(out, PluginGrant{Name: g.GetName(), Class: policy.Class(g.GetMaxClass()), Digest: g.GetDigest()})
	}
	return sortGrants(out)
}

// unionGrants is what a or b allows: each release of either, at the higher
// of its classes.
func unionGrants(a, b []PluginGrant) []PluginGrant {
	out := slices.Clone(a)
	for _, g := range b {
		i := slices.IndexFunc(out, func(o PluginGrant) bool { return o.Name == g.Name && o.Digest == g.Digest })
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
	slices.SortFunc(gs, func(a, b PluginGrant) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Digest, b.Digest)
	})
	return gs
}

// releaseOf is the release b offers.
func releaseOf(b *agentv1.PluginBinary) plugins.Release { return plugins.ReleaseOf(b) }

// pluginPin is a release pinned on first use, for the --allow-plugin flag
// Flag (NAME:CLASS): another flag pins anew.
type pluginPin struct {
	Flag   string `json:"flag"`
	Digest string `json:"digest"`
}

// pluginHost installs and runs the device's plugins.
type pluginHost struct {
	dir, pinsPath string
	log           *slog.Logger
	ceiling       func() Ceiling
	// opts bound a plugin's process; tests shorten them.
	opts plugins.Options
	// unsupported, when set, is why this platform runs no plugins.
	unsupported string
	// slots bounds the commands running at once.
	slots chan struct{}

	// gen numbers the configs received; a sync of an older one is
	// skipped. syncMu runs one sync at a time.
	gen    atomic.Uint64
	syncMu sync.Mutex

	mu        sync.Mutex
	installed map[string]installedPlugin
}

// installedPlugin is a release whose program is on disk, checked.
type installedPlugin struct {
	sha256   string
	digest   string
	version  string
	manifest plugins.Manifest
	release  *agentv1.PluginBinary
	// life ends when the release is removed or replaced: its commands in
	// flight are cancelled.
	life context.Context
	stop context.CancelFunc
}

// newPluginHost keeps the plugins under dataDir. The path is made absolute:
// a plugin's program is named relative to nothing else.
func newPluginHost(dataDir string, log *slog.Logger, ceiling func() Ceiling) *pluginHost {
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	h := &pluginHost{
		dir: filepath.Join(dataDir, PluginsDir), pinsPath: filepath.Join(dataDir, PluginPinsFile),
		log: log, ceiling: ceiling, installed: map[string]installedPlugin{}, slots: make(chan struct{}, maxPluginCommands),
	}
	if runtime.GOOS == "windows" {
		h.unsupported = "device plugins are not supported on Windows yet"
	}
	return h
}

// loadPins is the releases pinned on first use, by plugin name.
func (h *pluginHost) loadPins() map[string]pluginPin {
	pins := map[string]pluginPin{}
	b, err := os.ReadFile(h.pinsPath)
	if err == nil {
		err = json.Unmarshal(b, &pins)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		h.log.Warn("read the plugin pins", "err", err)
	}
	return pins
}

func (h *pluginHost) savePins(pins map[string]pluginPin) error {
	b, err := json.Marshal(pins)
	if err != nil {
		return err
	}
	tmp := h.pinsPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.pinsPath)
}

// flagOf is the --allow-plugin flag a grant without a digest came from.
func flagOf(g *agentv1.PluginGrant) string { return g.GetName() + ":" + g.GetMaxClass() }

// resolved is c with each grant without a digest pinned to the release
// pins hold for its flag; one without a pin stays without a digest.
func resolved(c *agentv1.Ceiling, pins map[string]pluginPin) *agentv1.Ceiling {
	out := &agentv1.Ceiling{}
	for _, g := range c.GetPlugins() {
		if g.GetDigest() == "" {
			if p, ok := pins[g.GetName()]; ok && p.Flag == flagOf(g) {
				g = &agentv1.PluginGrant{Name: g.GetName(), MaxClass: g.GetMaxClass(), Digest: p.Digest}
			}
		}
		out.Plugins = append(out.Plugins, g)
	}
	return out
}

// unpinned is the grant of plugin name without a digest nor a pin yet in
// c, if any: the first release installed is pinned to it.
func unpinned(c *agentv1.Ceiling, name string) *agentv1.PluginGrant {
	for _, g := range c.GetPlugins() {
		if g.GetName() == name && g.GetDigest() == "" {
			return g
		}
	}
	return nil
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
	pins := h.loadPins()
	h.mu.Lock()
	had := h.installed
	h.mu.Unlock()
	next := map[string]installedPlugin{}
	for _, name := range names {
		state := &agentv1.PluginState{Name: name}
		st.Plugins = append(st.Plugins, state)
		if h.unsupported != "" {
			state.Error = h.unsupported
			continue
		}
		b := mine[name]
		if b == nil {
			state.Error = fmt.Sprintf("no program uploaded for this device's platform, %s/%s", runtime.GOOS, runtime.GOARCH)
			continue
		}
		state.Version = b.GetVersion()
		c := resolved(h.ceiling().proto(), pins)
		inst, err := h.install(ctx, client, hub, c, pins, b)
		if err != nil {
			h.log.WarnContext(ctx, "plugin not installed", "plugin", name, "err", err)
			state.Error = err.Error()
			// The release the device runs stays while its ceiling allows it.
			old, ok := had[name]
			if !ok || policy.PluginWithinCeiling(c, name, old.digest, "") != nil {
				continue
			}
			inst = old
		}
		state.Version, state.Sha256, state.Release = inst.version, inst.sha256, inst.release
		next[name] = inst
	}
	h.mu.Lock()
	h.installed = next
	h.mu.Unlock()
	// Commands in flight of a release removed or replaced are cancelled.
	for name, old := range had {
		if n, ok := next[name]; (!ok || n.digest != old.digest) && old.stop != nil {
			old.stop()
		}
	}
	h.prune(ctx, next)
	return st
}

// install checks b against c, whose grants without a digest pins resolved,
// and makes sure its program is on disk. A release installed for a grant
// without a digest nor a pin is pinned to it.
func (h *pluginHost) install(ctx context.Context, client *http.Client, hub string, c *agentv1.Ceiling,
	pins map[string]pluginPin, b *agentv1.PluginBinary,
) (installedPlugin, error) {
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
	digest := releaseOf(b).Digest()
	var pin *agentv1.PluginGrant
	if err := policy.PluginWithinCeiling(c, b.GetName(), digest, ""); err != nil {
		if pin = unpinned(c, b.GetName()); pin == nil {
			return installedPlugin{}, fmt.Errorf("release %.12s (%s) is not the one this device allows: "+
				"approve it in the device's Capabilities, or pin it with --allow-plugin %s@%s: %w",
				digest, b.GetVersion(), b.GetName(), digest, err)
		}
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
	if sum, err := fileSHA256(path); err != nil || sum != b.GetSha256() {
		if used := h.diskUsed(); uint64(used)+b.GetSize() > maxPluginsDisk { //nolint:gosec // a sum of file sizes, never negative
			return installedPlugin{}, fmt.Errorf("the plugins would take more than %d MiB on this device", maxPluginsDisk>>20)
		}
		if err := h.download(ctx, client, hub, b.GetSha256(), path); err != nil {
			return installedPlugin{}, err
		}
		h.log.InfoContext(ctx, "plugin installed", "plugin", b.GetName(), "version", b.GetVersion(), "sha256", b.GetSha256(), "digest", digest)
	}
	if pin != nil {
		pins[b.GetName()] = pluginPin{Flag: flagOf(pin), Digest: digest}
		if err := h.savePins(pins); err != nil {
			return installedPlugin{}, fmt.Errorf("pin the release: %w", err)
		}
		h.log.InfoContext(ctx, "plugin release pinned on first use", "plugin", b.GetName(), "digest", digest)
	}
	h.mu.Lock()
	old, ok := h.installed[b.GetName()]
	h.mu.Unlock()
	if ok && old.digest == digest {
		return old, nil
	}
	life, stop := context.WithCancel(context.Background())
	return installedPlugin{
		sha256: b.GetSha256(), digest: digest, version: b.GetVersion(), manifest: m,
		release: proto.CloneOf(b), life: life, stop: stop,
	}, nil
}

// diskUsed is the bytes the plugins' files take.
func (h *pluginHost) diskUsed() int64 {
	var n int64
	_ = filepath.WalkDir(h.dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
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
	if h.unsupported != "" {
		return deny(errors.New(h.unsupported))
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
	if err := policy.PluginWithinCeiling(resolved(h.ceiling().proto(), h.loadPins()), req.GetPlugin(), inst.digest, class); err != nil {
		return deny(err)
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		return deny(fmt.Errorf("%d plugin commands already run on this device", maxPluginCommands))
	}
	// Removing or replacing the release cancels the command.
	if inst.life != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		defer context.AfterFunc(inst.life, cancel)()
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
