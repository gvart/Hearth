// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
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
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// Exec plugins on devices (#223), the agent stream's side. The hub holding
// an agent's stream sends it a PluginConfig, as it sends the ceiling
// (ceilingpush.go): on connect, an empty one too, and from every heartbeat
// and facts report when it changed. It holds every plugin uploaded for
// devices, for every platform, whose name the grants of the device allow
// (allowedPluginGrants): the agent picks its own platform's and checks the
// release against its own ceiling again.
// The agent fetches each program from this hub at plugins.BlobPath, with its
// client certificate, and answers with a PluginStatus, which the hub keeps
// for the stream.
//
// The programs are files in the data dir of the hub they were uploaded to
// (PluginBlobs), never in the store; another hub fetches one it lacks from
// that hub over the masters' link, and checks its SHA-256.

// minPluginMinor is the first agent protocol minor version that takes
// PluginRequests.
const minPluginMinor = 14

// ErrPluginTooLarge is a program larger than plugins.MaxProgramSize.
var ErrPluginTooLarge = fmt.Errorf("the program is larger than %d MiB", plugins.MaxProgramSize>>20)

// PluginBlobs holds the programs of the plugins uploaded for devices, each
// in a file named by its SHA-256, 0600, in a directory of the hub's data dir.
type PluginBlobs struct {
	dir string
	// masters, in an AP cluster, reach the hub holding a program this one
	// lacks.
	masters Masters
}

// PluginBlobsDir is the directory of a hub's data dir that holds the
// programs.
const PluginBlobsDir = "plugin-blobs"

// NewPluginBlobs returns the programs held in dataDir.
func NewPluginBlobs(dataDir string) *PluginBlobs {
	return &PluginBlobs{dir: filepath.Join(dataDir, PluginBlobsDir)}
}

// Save stores the program r reads, at most plugins.MaxProgramSize bytes, and
// returns its SHA-256 and size. A larger one fails with ErrPluginTooLarge and
// leaves nothing behind.
func (b *PluginBlobs) Save(r io.Reader) (string, int64, error) {
	p, err := b.Stage(r)
	if err != nil {
		return "", 0, err
	}
	if err := p.Commit(); err != nil {
		return "", 0, err
	}
	return p.SHA256, p.Size, nil
}

// StagedProgram is a program read and hashed, not stored yet: Commit stores
// it under its SHA-256, Discard drops it. An upload is staged until policy
// decided on it, so a refused one never shows under a SHA-256.
type StagedProgram struct {
	SHA256 string
	Size   int64
	path   string
	dir    string
}

// Commit stores p under its SHA-256. The same program stored meanwhile is
// the same bytes.
func (p *StagedProgram) Commit() error {
	if err := os.Rename(p.path, filepath.Join(p.dir, p.SHA256)); err != nil {
		return fmt.Errorf("store the program: %w", err)
	}
	return nil
}

// Discard drops p, unless it was committed.
func (p *StagedProgram) Discard() { _ = os.Remove(p.path) }

// Stage reads the program r reads, at most plugins.MaxProgramSize bytes,
// into a file of its own; ErrPluginTooLarge leaves nothing behind.
func (b *PluginBlobs) Stage(r io.Reader) (*StagedProgram, error) {
	return b.stage(r, "")
}

// stage stages r, refusing it unless its SHA-256 is want, when set.
func (b *PluginBlobs) stage(r io.Reader, want string) (*StagedProgram, error) {
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return nil, fmt.Errorf("store the program: %w", err)
	}
	tmp, err := os.CreateTemp(b.dir, ".upload-*")
	if err != nil {
		return nil, fmt.Errorf("store the program: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, plugins.MaxProgramSize+1))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	sum := hex.EncodeToString(h.Sum(nil))
	switch {
	case err != nil:
		err = fmt.Errorf("store the program: %w", err)
	case n > plugins.MaxProgramSize:
		err = ErrPluginTooLarge
	case want != "" && sum != want:
		err = fmt.Errorf("store the program: its SHA-256 is %s, not %s: %w", sum, want, plugins.ErrPinMismatch)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	return &StagedProgram{SHA256: sum, Size: n, path: tmp.Name(), dir: b.dir}, nil
}

// Open opens the program of SHA-256 sum: this hub's copy, or one fetched
// from holder, the hub it was uploaded to, and checked.
func (b *PluginBlobs) Open(ctx context.Context, sum, holder string) (*os.File, error) {
	if !plugins.ValidSHA256(sum) {
		return nil, fmt.Errorf("program %q: %w", sum, store.ErrNotFound)
	}
	path := filepath.Join(b.dir, sum)
	f, err := os.Open(path) //nolint:gosec // named by a checked SHA-256 under the data dir
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return f, err
	}
	if b.masters == nil || holder == "" || holder == b.masters.Self() {
		return nil, fmt.Errorf("program %.12s is not on this hub: %w", sum, store.ErrNotFound)
	}
	// The row naming holder is replicated: never dial a hub that is not a
	// live master of the cluster.
	if !b.masters.Live(holder) {
		return nil, fmt.Errorf("program %.12s: its hub %s is not a live master: %w", sum, holder, store.ErrNotFound)
	}
	if err := b.fetch(ctx, sum, holder); err != nil {
		return nil, err
	}
	return os.Open(path) //nolint:gosec // as above
}

// fetch copies the program of SHA-256 sum from master over the link.
func (b *PluginBlobs) fetch(ctx context.Context, sum, master string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+master+"/agents/plugin-blobs/"+sum, nil) //nolint:gosec // a cluster master over the pinned link; sum is a checked SHA-256
	if err != nil {
		return err
	}
	resp, err := b.masters.Client().Do(req) //nolint:gosec // as above
	if err != nil {
		return fmt.Errorf("fetch program %.12s from hub %s: %w", sum, master, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch program %.12s from hub %s: %s: %w", sum, master, resp.Status, store.ErrNotFound)
	}
	p, err := b.stage(resp.Body, sum)
	if err == nil {
		err = p.Commit()
	}
	if err != nil {
		return fmt.Errorf("fetch program %.12s from hub %s: %w", sum, master, err)
	}
	return nil
}

// Remove deletes this hub's copy of the program of SHA-256 sum, if any.
func (b *PluginBlobs) Remove(sum string) error {
	if !plugins.ValidSHA256(sum) {
		return nil
	}
	if err := os.Remove(filepath.Join(b.dir, sum)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// serveLocal serves this hub's copy of the program named by the request's
// path, to another master over the link.
func (b *PluginBlobs) serveLocal(w http.ResponseWriter, r *http.Request) {
	sum := r.PathValue("sum")
	if !plugins.ValidSHA256(sum) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(b.dir, sum))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()
	serveProgram(w, r, f)
}

func serveProgram(w http.ResponseWriter, r *http.Request, f *os.File) {
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "cannot read the program", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", fi.ModTime(), f)
}

// DevicePluginManifest is what the store keeps of a device plugin's
// manifest: what its agent needs to run it. Never an env.
type DevicePluginManifest struct {
	Args         []string              `json:"args"`
	Capabilities []string              `json:"capabilities"`
	Commands     []plugins.CommandSpec `json:"commands"`
}

// decodeManifest is p's manifest.
func decodeManifest(p store.DevicePlugin) (DevicePluginManifest, error) {
	var m DevicePluginManifest
	if err := json.Unmarshal(p.Manifest, &m); err != nil {
		return m, fmt.Errorf("decode the manifest of plugin %s: %w", p.Name, err)
	}
	return m, nil
}

// pluginBinary is p as an agent gets it.
func pluginBinary(p store.DevicePlugin) (*agentv1.PluginBinary, error) {
	m, err := decodeManifest(p)
	if err != nil {
		return nil, err
	}
	b := &agentv1.PluginBinary{
		Name: p.Name, Version: p.Version, Os: p.OS, Arch: p.Arch, Sha256: p.SHA256, Size: uint64(max(p.Size, 0)),
		Args: m.Args, Capabilities: m.Capabilities,
	}
	for _, c := range m.Commands {
		b.Commands = append(b.Commands, &agentv1.PluginCommandSpec{Name: c.Name, Class: string(c.Class), Description: c.Description})
	}
	return b, nil
}

// SetPlugins makes a hand the plugins uploaded to st, with their programs
// in blobs, to the agents that stream to it.
func (a *Agents) SetPlugins(st *store.Store, blobs *PluginBlobs) {
	list := st.DevicePlugins()
	a.devicePlugins, a.pluginStore, a.blobs = &list, st, blobs
	if a.masters != nil && blobs != nil {
		blobs.masters = a.masters
	}
}

// allowedPluginGrants are the grants of reported, the ceiling device d's
// agent reported, that the hub knows of: one the hub set for d (unless its
// agent runs --local-ceiling) or one d reported as its own flags, each at
// the lower of the two classes. A device cannot make the hub hand it a
// plugin by reporting a grant no one set. The agent checks its own ceiling
// again.
func allowedPluginGrants(ctx context.Context, st *store.Store, d store.Device, reported *agentv1.Ceiling) (*agentv1.Ceiling, error) {
	caps, err := capabilitiesOf(ctx, st, d)
	if err != nil {
		return nil, err
	}
	var sources []PluginGrant
	if caps.Local != nil {
		sources = append(sources, caps.Local.Plugins...)
	}
	if !caps.Locked {
		sources = append(sources, caps.Hub.Plugins...)
	}
	out := &agentv1.Ceiling{}
	for _, g := range reported.GetPlugins() {
		var known policy.Class
		for _, s := range sources {
			if s.Name == g.GetName() && s.Digest == g.GetDigest() && (known == "" || policy.ClassAbove(s.Class, known)) {
				known = s.Class
			}
		}
		if known == "" {
			continue
		}
		class := policy.Class(g.GetMaxClass())
		if policy.ClassAbove(class, known) {
			class = known
		}
		out.Plugins = append(out.Plugins, &agentv1.PluginGrant{Name: g.GetName(), MaxClass: string(class), Digest: g.GetDigest()})
	}
	return out, nil
}

// grantedClass is the highest class c allows for the commands of release
// digest of plugin name: by a grant pinned to it, or by one of the agent's
// own flags that pins none, for which the agent pinned the first release it
// installed and checks it.
func grantedClass(c *agentv1.Ceiling, name, digest string) (policy.Class, bool) {
	var best policy.Class
	found := false
	for _, g := range c.GetPlugins() {
		if g.GetName() != name || (g.GetDigest() != "" && g.GetDigest() != digest) {
			continue
		}
		if cl := policy.Class(g.GetMaxClass()); !found || policy.ClassAbove(cl, best) {
			best, found = cl, true
		}
	}
	return best, found
}

// pluginGrants are the grants allowedPluginGrants keeps of what the agent of
// device reported on sess.
func (a *Agents) pluginGrants(ctx context.Context, device string, sess *agentSession) (*agentv1.Ceiling, error) {
	sess.mu.Lock()
	reported := sess.ceiling
	sess.mu.Unlock()
	if a.pluginStore == nil {
		return &agentv1.Ceiling{}, nil
	}
	d, err := a.pluginStore.Devices().Get(ctx, device)
	if err != nil {
		return nil, err
	}
	return allowedPluginGrants(ctx, a.pluginStore, d, reported)
}

// syncPlugins sends sess the plugins its agent may install when they differ
// from the ones it last got. A failed read or send is logged: the next
// heartbeat tries again.
func (s *AgentStream) syncPlugins(ctx context.Context, log *slog.Logger, sess *agentSession) {
	if err := s.agents.syncPlugins(ctx, sess); err != nil {
		log.WarnContext(ctx, "send the device's plugins", "err", err)
	}
}

func (a *Agents) syncPlugins(ctx context.Context, sess *agentSession) error {
	if a.devicePlugins == nil || sess.minor < minPluginMinor {
		return nil
	}
	sess.pluginMu.Lock()
	defer sess.pluginMu.Unlock()
	list, err := a.devicePlugins.List(ctx)
	if err != nil {
		return fmt.Errorf("read the plugins: %w", err)
	}
	c, err := a.pluginGrants(ctx, sess.device, sess)
	if err != nil {
		return fmt.Errorf("read the device's plugin grants: %w", err)
	}
	cfg := &agentv1.PluginConfig{}
	for _, p := range list {
		if _, ok := policy.PluginGrantOf(c, p.Name); !ok {
			continue
		}
		b, err := pluginBinary(p)
		if err != nil {
			return err
		}
		cfg.Plugins = append(cfg.Plugins, b)
	}
	if sess.sentPlugins != nil && proto.Equal(cfg, sess.sentPlugins) {
		return nil
	}
	msg := &agentv1.HubMessage{Payload: &agentv1.HubMessage_PluginRequest{PluginRequest: &agentv1.PluginRequest{
		Op: &agentv1.PluginRequest_Config{Config: cfg},
	}}}
	if err := sess.sendMsg(msg); err != nil {
		return err
	}
	sess.sentPlugins = cfg
	return nil
}

// PushPlugins sends every agent streaming to this hub its plugins, as they
// are now in the store. Agents streaming elsewhere get them from their next
// heartbeat there.
func (a *Agents) PushPlugins(ctx context.Context) error {
	a.mu.Lock()
	sessions := make([]*agentSession, 0, len(a.sessions))
	for _, s := range a.sessions {
		sessions = append(sessions, s)
	}
	a.mu.Unlock()
	var errs []error
	for _, s := range sessions {
		if err := a.syncPlugins(ctx, s); err != nil {
			errs = append(errs, fmt.Errorf("device %s: %w", s.device, err))
		}
	}
	return errors.Join(errs...)
}

// pluginEvent takes what the agent's plugins did.
func (s *agentSession) pluginEvent(ev *agentv1.PluginEvent) {
	switch e := ev.GetEvent().(type) {
	case *agentv1.PluginEvent_Status:
		s.mu.Lock()
		s.pluginStatus = e.Status
		s.mu.Unlock()
	case *agentv1.PluginEvent_Result:
		s.mu.Lock()
		ch := s.pluginRuns[e.Result.GetId()]
		delete(s.pluginRuns, e.Result.GetId())
		s.mu.Unlock()
		if ch != nil {
			ch <- e.Result
		}
	}
}

// pluginBlobHandler serves an agent the program of a plugin it may install:
// one uploaded for devices whose release the device's grants
// (allowedPluginGrants) allow. requireClientCert authenticated the device.
func (a *Agents) pluginBlobHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		device, ok := deviceIDFrom(ctx)
		sum := strings.TrimPrefix(r.URL.Path, plugins.BlobPath)
		if !ok || r.Method != http.MethodGet || !plugins.ValidSHA256(sum) || a.devicePlugins == nil || a.blobs == nil {
			http.NotFound(w, r)
			return
		}
		a.mu.Lock()
		sess := a.sessions[device]
		a.mu.Unlock()
		if sess == nil {
			http.Error(w, "the device has no stream to this hub", http.StatusForbidden)
			return
		}
		c, err := a.pluginGrants(ctx, device, sess)
		if err != nil {
			http.Error(w, "cannot read the device's plugin grants", http.StatusServiceUnavailable)
			return
		}
		list, err := a.devicePlugins.List(ctx)
		if err != nil {
			http.Error(w, "cannot read the plugins", http.StatusServiceUnavailable)
			return
		}
		i := slices.IndexFunc(list, func(p store.DevicePlugin) bool {
			if p.SHA256 != sum {
				return false
			}
			b, err := pluginBinary(p)
			if err != nil {
				return false
			}
			_, allowed := grantedClass(c, p.Name, plugins.ReleaseOf(b).Digest())
			return allowed
		})
		if i < 0 {
			http.Error(w, "no plugin program for this device", http.StatusNotFound)
			return
		}
		f, err := a.blobs.Open(ctx, sum, list[i].Holder)
		if err != nil {
			http.Error(w, "the program is not on this hub", http.StatusNotFound)
			return
		}
		defer func() { _ = f.Close() }()
		serveProgram(w, r, f)
	})
}

// checkPlugin refuses a command of class of release digest of plugin name
// unless the agent runs plugins and its grants (allowedPluginGrants) allow
// the release up to class.
func (a *Agents) checkPlugin(ctx context.Context, s *agentSession, device, name, digest string, class policy.Class) error {
	if s.minor < minPluginMinor {
		return fmt.Errorf("device %s: %w", device, errPluginsNeedUpgrade)
	}
	c, err := a.pluginGrants(ctx, device, s)
	if err != nil {
		return err
	}
	limit, ok := grantedClass(c, name, digest)
	switch {
	case !ok:
		return fmt.Errorf("device %s: plugin %s: release %.12s is not allowed there: %w", device, name, digest, policy.ErrBeyondCeiling)
	case class != "" && !policy.Within(class, limit):
		return fmt.Errorf("device %s: plugin %s: a %s command is above the %s the device allows: %w", device, name, class, limit, policy.ErrBeyondCeiling)
	}
	return nil
}

// errPluginsNeedUpgrade refuses a plugin command for an agent older than
// minPluginMinor.
var errPluginsNeedUpgrade = fmt.Errorf("its agent is too old for plugins; upgrade it: %w", policy.ErrBeyondCeiling)

// CheckPlugin reports whether a command of class of release digest of
// plugin name would be sent to the agent of device: it fails with an error
// wrapping policy.ErrBeyondCeiling when the agent is too old for plugins or
// its grants do not allow the release up to class, and with
// ErrAgentNotConnected when it has no open stream to this hub.
func (a *Agents) CheckPlugin(ctx context.Context, device, name, digest string, class policy.Class) error {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		_, err := a.call(ctx, master, opPlugin, agentCall{Device: id, CheckOnly: true, Class: string(class), Digest: digest},
			&agentv1.PluginCommand{Plugin: name}, nil)
		return err
	}
	if err != nil {
		return err
	}
	return a.checkPlugin(ctx, s, device, name, digest, class)
}

// PluginStatus is the state of the plugins of device's agent, as it last
// reported it; nil until it did.
func (a *Agents) PluginStatus(ctx context.Context, device string) (*agentv1.PluginStatus, error) {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		res := &agentv1.PluginStatus{}
		if _, err := a.call(ctx, master, opPluginStatus, agentCall{Device: id}, nil, res); err != nil {
			return nil, err
		}
		if res.GetOs() == "" {
			return nil, nil
		}
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pluginStatus, nil
}

// Plugin sends req, a command of class of release digest, to the agent of
// device, asking it to finish within timeout, and waits for its result, as
// Exec does. A command the device's grants do not allow is never sent.
func (a *Agents) Plugin(ctx context.Context, device, digest string, class policy.Class, req *agentv1.PluginCommand, timeout time.Duration) (*agentv1.PluginResult, error) {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		res := &agentv1.PluginResult{}
		in := agentCall{Device: id, TimeoutMS: timeout.Milliseconds(), Class: string(class), Digest: digest}
		if _, err := a.call(ctx, master, opPlugin, in, req, res); err != nil {
			return nil, err
		}
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	if err := a.checkPlugin(ctx, s, device, req.GetPlugin(), digest, class); err != nil {
		return nil, err
	}
	req.Id = strings.ToLower(rand.Text())
	req.Timeout = durationpb.New(timeout)
	return roundTrip(ctx, s, device, s.pluginRuns, req.Id,
		&agentv1.HubMessage{Payload: &agentv1.HubMessage_PluginRequest{PluginRequest: &agentv1.PluginRequest{
			Op: &agentv1.PluginRequest_Command{Command: req},
		}}})
}

// The forwarded operations of device plugins.
const (
	opPlugin       = "plugin"
	opPluginStatus = "plugin-status"
)

// pluginOps registers the forwarded plugin operations, and the programs
// this hub holds, on the masters' link.
func pluginOps(a *Agents, mux *http.ServeMux, handle func(op string, fn func(ctx context.Context, in agentCall) (proto.Message, string, error))) {
	handle(opPlugin, func(ctx context.Context, in agentCall) (proto.Message, string, error) {
		req := &agentv1.PluginCommand{}
		if err := protojson.Unmarshal(in.Req, req); err != nil {
			return nil, "", err
		}
		if in.CheckOnly {
			return nil, "", a.CheckPlugin(ctx, in.Device, req.GetPlugin(), in.Digest, policy.Class(in.Class))
		}
		res, err := a.Plugin(ctx, in.Device, in.Digest, policy.Class(in.Class), req, time.Duration(in.TimeoutMS)*time.Millisecond)
		return res, "", err
	})
	handle(opPluginStatus, func(ctx context.Context, in agentCall) (proto.Message, string, error) {
		st, err := a.PluginStatus(ctx, in.Device)
		if st == nil {
			st = &agentv1.PluginStatus{}
		}
		return st, "", err
	})
	mux.HandleFunc("GET /agents/plugin-blobs/{sum}", func(w http.ResponseWriter, r *http.Request) {
		if a.blobs == nil {
			http.NotFound(w, r)
			return
		}
		a.blobs.serveLocal(w, r)
	})
}
