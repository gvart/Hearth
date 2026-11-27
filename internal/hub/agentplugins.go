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
// devices, for every platform, whose name the ceiling the agent reported
// allows: the agent picks its own platform's and checks the grant again.
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
	return b.save(r, "")
}

// save stores r, refusing it unless its SHA-256 is want, when set.
func (b *PluginBlobs) save(r io.Reader, want string) (string, int64, error) {
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return "", 0, fmt.Errorf("store the program: %w", err)
	}
	tmp, err := os.CreateTemp(b.dir, ".upload-*")
	if err != nil {
		return "", 0, fmt.Errorf("store the program: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, plugins.MaxProgramSize+1))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return "", 0, fmt.Errorf("store the program: %w", err)
	case n > plugins.MaxProgramSize:
		return "", 0, ErrPluginTooLarge
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if want != "" && sum != want {
		return "", 0, fmt.Errorf("store the program: its SHA-256 is %s, not %s: %w", sum, want, plugins.ErrPinMismatch)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(b.dir, sum)); err != nil {
		return "", 0, fmt.Errorf("store the program: %w", err)
	}
	return sum, n, nil
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
	if err := b.fetch(ctx, sum, holder); err != nil {
		return nil, err
	}
	return os.Open(path) //nolint:gosec // as above
}

// fetch copies the program of SHA-256 sum from master over the link.
func (b *PluginBlobs) fetch(ctx context.Context, sum, master string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+master+"/agents/plugin-blobs/"+sum, nil)
	if err != nil {
		return err
	}
	resp, err := b.masters.Client().Do(req)
	if err != nil {
		return fmt.Errorf("fetch program %.12s from hub %s: %w", sum, master, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch program %.12s from hub %s: %s: %w", sum, master, resp.Status, store.ErrNotFound)
	}
	if _, _, err := b.save(resp.Body, sum); err != nil {
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
	f, err := os.Open(filepath.Join(b.dir, sum)) //nolint:gosec // named by a checked SHA-256 under the data dir
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

// SetPlugins makes a hand the plugins of list, with their programs in blobs,
// to the agents that stream to it.
func (a *Agents) SetPlugins(list store.DevicePlugins, blobs *PluginBlobs) {
	a.devicePlugins, a.blobs = &list, blobs
	if a.masters != nil && blobs != nil {
		blobs.masters = a.masters
	}
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
	sess.mu.Lock()
	c := sess.ceiling
	sess.mu.Unlock()
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
// one uploaded for devices, whose name the ceiling the agent reported on its
// stream to this hub allows. requireClientCert authenticated the device.
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
		sess.mu.Lock()
		c := sess.ceiling
		sess.mu.Unlock()
		list, err := a.devicePlugins.List(ctx)
		if err != nil {
			http.Error(w, "cannot read the plugins", http.StatusServiceUnavailable)
			return
		}
		i := slices.IndexFunc(list, func(p store.DevicePlugin) bool {
			_, allowed := policy.PluginGrantOf(c, p.Name)
			return p.SHA256 == sum && allowed
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

// checkPlugin refuses a command of class of plugin name unless the agent
// runs plugins and the ceiling it reported allows it.
func (s *agentSession) checkPlugin(device, name string, class policy.Class) error {
	if s.minor < minPluginMinor {
		return fmt.Errorf("device %s: %w", device, errPluginsNeedUpgrade)
	}
	s.mu.Lock()
	c := s.ceiling
	s.mu.Unlock()
	if err := policy.PluginWithinCeiling(c, name, class); err != nil {
		return fmt.Errorf("device %s: %w", device, err)
	}
	return nil
}

// errPluginsNeedUpgrade refuses a plugin command for an agent older than
// minPluginMinor.
var errPluginsNeedUpgrade = fmt.Errorf("its agent is too old for plugins; upgrade it: %w", policy.ErrBeyondCeiling)

// CheckPlugin reports whether a command of class of plugin name would be
// sent to the agent of device: it fails with an error wrapping
// policy.ErrBeyondCeiling when the agent is too old for plugins or its
// reported ceiling does not allow the plugin up to class, and with
// ErrAgentNotConnected when it has no open stream to this hub.
func (a *Agents) CheckPlugin(ctx context.Context, device, name string, class policy.Class) error {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		_, err := a.call(ctx, master, opPlugin, agentCall{Device: id, CheckOnly: true, Class: string(class)},
			&agentv1.PluginCommand{Plugin: name}, nil)
		return err
	}
	if err != nil {
		return err
	}
	return s.checkPlugin(device, name, class)
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

// Plugin sends req, a command of class, to the agent of device, asking it to
// finish within timeout, and waits for its result, as Exec does. A command
// the agent's reported ceiling does not allow is never sent.
func (a *Agents) Plugin(ctx context.Context, device string, class policy.Class, req *agentv1.PluginCommand, timeout time.Duration) (*agentv1.PluginResult, error) {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		res := &agentv1.PluginResult{}
		in := agentCall{Device: id, TimeoutMS: timeout.Milliseconds(), Class: string(class)}
		if _, err := a.call(ctx, master, opPlugin, in, req, res); err != nil {
			return nil, err
		}
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.checkPlugin(device, req.GetPlugin(), class); err != nil {
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
			return nil, "", a.CheckPlugin(ctx, in.Device, req.GetPlugin(), policy.Class(in.Class))
		}
		res, err := a.Plugin(ctx, in.Device, policy.Class(in.Class), req, time.Duration(in.TimeoutMS)*time.Millisecond)
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
