// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// Exec plugins on devices (#223), the API's side: the plugins uploaded for
// devices, each for one platform, and the commands of the plugins a
// device's agent installed, run through policy as
// device.plugin.command.<class>, of the class the uploaded manifest declares.

const (
	// devicePluginTimeout is how long the agent has for a plugin command,
	// and devicePluginGrace how much longer the hub waits for its answer.
	devicePluginTimeout = 30 * time.Second
	devicePluginGrace   = 5 * time.Second
)

// devicePluginActions are the policy actions of device plugin commands, by
// the class the manifest declares.
var devicePluginActions = map[policy.Class]policy.Action{
	policy.Read: policy.DevicePluginCommandRead, policy.Safe: policy.DevicePluginCommandSafe,
	policy.Dangerous: policy.DevicePluginCommandDangerous,
}

// ErrPluginNotInstalled is a command for a plugin the device's agent has not
// installed: not allowed, not yet fetched, or failed.
var ErrPluginNotInstalled = errors.New("the plugin is not installed on the device")

// platformRE is what Go's os and arch names look like.
var platformRE = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// DevicePluginUpload is a plugin being uploaded for devices: its manifest,
// and its program, already stored.
type DevicePluginUpload struct {
	Manifest plugins.Manifest
	OS, Arch string
	SHA256   string
	Size     int64
}

// CheckPlatform checks os and arch as Go names them, such as linux and
// arm64.
func CheckPlatform(os, arch string) error {
	if !platformRE.MatchString(os) || !platformRE.MatchString(arch) {
		return fmt.Errorf("platform %q/%q: want Go's names, such as linux and arm64", os, arch)
	}
	return nil
}

// Request is the upload as the policy request plugin.binary.upload: its
// detail says what would run on devices.
func (u DevicePluginUpload) Request() policy.Request {
	return policy.Request{
		Action: policy.PluginBinaryUpload, Target: u.Manifest.Name,
		Detail: map[string]any{
			"plugin": u.Manifest.Name, "version": u.Manifest.Version, "os": u.OS, "arch": u.Arch,
			"sha256": u.SHA256, "size": u.Size,
		},
	}
}

// Save records the upload in st, its program held by holder (a hub's node
// id; empty on a single hub), uploaded by by at now.
func (u DevicePluginUpload) Save(ctx context.Context, st *store.Store, holder, by string, now time.Time) error {
	m, err := json.Marshal(DevicePluginManifest{
		Args: nonNil(u.Manifest.Args), Capabilities: nonNil(u.Manifest.Capabilities), Commands: u.Manifest.Commands,
	})
	if err != nil {
		return err
	}
	return st.DevicePlugins().Set(ctx, store.DevicePlugin{
		Name: u.Manifest.Name, OS: u.OS, Arch: u.Arch, Version: u.Manifest.Version, SHA256: u.SHA256, Size: u.Size,
		Manifest: m, Holder: holder, UploadedAt: now, UploadedBy: by,
	})
}

// DevicePluginJSON is a plugin uploaded for devices, for one platform.
type DevicePluginJSON struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	OS           string                `json:"os"`
	Arch         string                `json:"arch"`
	Version      string                `json:"version"`
	SHA256       string                `json:"sha256"`
	Size         int64                 `json:"size"`
	Capabilities []string              `json:"capabilities"`
	Commands     []plugins.CommandSpec `json:"commands"`
	UploadedAt   time.Time             `json:"uploaded_at"`
	UploadedBy   string                `json:"uploaded_by"`
}

// DevicePluginsJSON answers GET /api/v1/device-plugins.
type DevicePluginsJSON struct {
	Plugins []DevicePluginJSON `json:"plugins"`
	// MaxSize is the largest program the hub takes, in bytes.
	MaxSize int64 `json:"max_size"`
}

// devicePluginJSON is p as served.
func devicePluginJSON(p store.DevicePlugin) (DevicePluginJSON, error) {
	m, err := decodeManifest(p)
	if err != nil {
		return DevicePluginJSON{}, err
	}
	commands := m.Commands
	if commands == nil {
		commands = []plugins.CommandSpec{}
	}
	return DevicePluginJSON{
		ID: p.ID, Name: p.Name, OS: p.OS, Arch: p.Arch, Version: p.Version, SHA256: p.SHA256, Size: p.Size,
		Capabilities: nonNil(m.Capabilities), Commands: commands, UploadedAt: p.UploadedAt.UTC(), UploadedBy: p.UploadedBy,
	}, nil
}

// ListDevicePlugins is every plugin uploaded for devices.
func ListDevicePlugins(ctx context.Context, st *store.Store) ([]DevicePluginJSON, error) {
	list, err := st.DevicePlugins().List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DevicePluginJSON, 0, len(list))
	for _, p := range list {
		j, err := devicePluginJSON(p)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, nil
}

// Previous is the SHA-256 of the program uploaded for the
// platform of u before it, or "" for none.
func (u DevicePluginUpload) Previous(ctx context.Context, st *store.Store) (string, error) {
	list, err := st.DevicePlugins().List(ctx)
	if err != nil {
		return "", err
	}
	id := store.DevicePluginID(u.Manifest.Name, u.OS, u.Arch)
	if i := slices.IndexFunc(list, func(p store.DevicePlugin) bool { return p.ID == id }); i >= 0 {
		return list[i].SHA256, nil
	}
	return "", nil
}

// RemoveDevicePluginBlob deletes the program of SHA-256 sum from blobs
// unless a plugin uploaded for devices still names it.
func RemoveDevicePluginBlob(ctx context.Context, st *store.Store, blobs *PluginBlobs, sum string) error {
	list, err := st.DevicePlugins().List(ctx)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(list, func(p store.DevicePlugin) bool { return p.SHA256 == sum }) {
		return nil
	}
	return blobs.Remove(sum)
}

func (a *api) devicePluginRoutes(mux *http.ServeMux) {
	if a.agents == nil || a.agents.blobs == nil {
		return
	}
	mux.Handle("GET /api/v1/device-plugins", a.auth(a.listDevicePlugins))
	mux.Handle("POST /api/v1/device-plugins", a.auth(a.uploadDevicePlugin))
	mux.Handle("DELETE /api/v1/device-plugins/{pid}", a.auth(a.deleteDevicePlugin))
	mux.Handle("GET /api/v1/devices/{id}/plugins", a.auth(a.deviceDevicePlugins))
	mux.Handle("POST /api/v1/devices/{id}/plugins/{name}/commands", a.auth(a.devicePluginCommand))
}

func (a *api) listDevicePlugins(w http.ResponseWriter, r *http.Request) {
	list, err := ListDevicePlugins(r.Context(), a.store)
	if err != nil {
		a.writeActionError(w, r, "list the device plugins", err)
		return
	}
	writeJSON(w, http.StatusOK, DevicePluginsJSON{Plugins: list, MaxSize: plugins.MaxProgramSize})
}

// uploadDevicePlugin serves POST /api/v1/device-plugins?os=&arch=: a
// multipart form whose first part, manifest, is the plugin's manifest
// (YAML) and whose second, program, is its program, streamed to the hub's
// data dir. It is plugin.binary.upload, dangerous: the session must have
// entered the admin password again.
func (a *api) uploadDevicePlugin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	goos, arch := r.URL.Query().Get("os"), r.URL.Query().Get("arch")
	if err := CheckPlatform(goos, arch); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	reauth := a.recentAuth(r)
	actor := func(req policy.Request) policy.Request {
		req.ActorKind, req.ActorID, req.Precheck = policy.ActorWeb, remoteHost(r), reauth
		return req
	}
	// Refused, and audited, before the program is read.
	if a.reauthUntil(r).IsZero() {
		err := a.policy.Do(ctx, actor(policy.Request{Action: policy.PluginBinaryUpload, Target: "device-plugins"}),
			func(context.Context) error { return nil })
		a.writeActionError(w, r, "upload the plugin", err)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "multipart/form-data" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be multipart/form-data")
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be a multipart form: manifest, then program")
		return
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "manifest" {
		writeError(w, http.StatusBadRequest, "bad_request", "the first part must be the manifest")
		return
	}
	mb, err := io.ReadAll(io.LimitReader(part, 64<<10+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "cannot read the manifest")
		return
	}
	m, err := plugins.ParseManifest(mb)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	part, err = mr.NextPart()
	if err != nil || part.FormName() != "program" {
		writeError(w, http.StatusBadRequest, "bad_request", "the second part must be the program")
		return
	}
	sum, size, err := a.agents.blobs.Save(part)
	switch {
	case errors.Is(err, ErrPluginTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", err.Error())
		return
	case err != nil:
		a.writeActionError(w, r, "store the plugin's program", err)
		return
	}
	u := DevicePluginUpload{Manifest: m, OS: goos, Arch: arch, SHA256: sum, Size: size}
	previous, err := u.Previous(ctx, a.store)
	if err != nil {
		a.writeActionError(w, r, "list the device plugins", err)
		return
	}
	holder := ""
	if a.masters != nil {
		holder = a.masters.Self()
	}
	err = a.policy.Do(ctx, actor(u.Request()), func(ctx context.Context) error {
		return u.Save(ctx, a.store, holder, policy.ActorWeb+"/"+remoteHost(r), a.now())
	})
	if err != nil {
		if rerr := RemoveDevicePluginBlob(context.WithoutCancel(ctx), a.store, a.agents.blobs, sum); rerr != nil {
			a.log.WarnContext(ctx, "remove a refused plugin's program", "sha256", sum, "err", rerr)
		}
		if errors.Is(err, store.ErrSchemaTooOld) {
			writeError(w, http.StatusConflict, "schema_too_old", "the hub cluster's database predates device plugins: upgrade every hub of the cluster first")
			return
		}
		a.writeActionError(w, r, "upload the plugin", err)
		return
	}
	// The program it replaces goes, here; a copy another master fetched
	// stays there.
	if previous != "" && previous != sum {
		if err := RemoveDevicePluginBlob(ctx, a.store, a.agents.blobs, previous); err != nil {
			a.log.WarnContext(ctx, "remove a replaced plugin's program", "sha256", previous, "err", err)
		}
	}
	a.log.InfoContext(ctx, "device plugin uploaded", "plugin", m.Name, "version", m.Version, "os", goos, "arch", arch, "sha256", sum)
	a.pushPlugins(ctx)
	j, err := ListDevicePlugins(ctx, a.store)
	if err != nil {
		a.writeActionError(w, r, "list the device plugins", err)
		return
	}
	i := slices.IndexFunc(j, func(p DevicePluginJSON) bool { return p.ID == store.DevicePluginID(m.Name, goos, arch) })
	if i < 0 {
		writeError(w, http.StatusConflict, "conflict", "the plugin was replaced or removed meanwhile")
		return
	}
	writeJSON(w, http.StatusCreated, j[i])
}

// pushPlugins sends the agents streaming here their plugins at once.
func (a *api) pushPlugins(ctx context.Context) {
	if err := a.agents.PushPlugins(ctx); err != nil {
		// Their next heartbeat sends them again.
		a.log.WarnContext(ctx, "send the devices their plugins", "err", err)
	}
}

// deleteDevicePlugin serves DELETE /api/v1/device-plugins/{pid}: the
// plugin of one platform is removed, and the agents remove it at their next
// sync. It is plugin.binary.delete.
func (a *api) deleteDevicePlugin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("pid")
	list, err := a.store.DevicePlugins().List(ctx)
	if err != nil {
		a.writeActionError(w, r, "list the device plugins", err)
		return
	}
	i := slices.IndexFunc(list, func(p store.DevicePlugin) bool { return p.ID == id })
	if i < 0 {
		writeError(w, http.StatusNotFound, "not_found", "no such device plugin")
		return
	}
	p := list[i]
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.PluginBinaryDelete, Target: p.Name,
		Detail: map[string]any{"plugin": p.Name, "version": p.Version, "os": p.OS, "arch": p.Arch, "sha256": p.SHA256},
	}, func(ctx context.Context) error { return a.store.DevicePlugins().Remove(ctx, id) })
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such device plugin")
		return
	case err != nil:
		a.writeActionError(w, r, "remove the device plugin", err)
		return
	}
	if err := RemoveDevicePluginBlob(ctx, a.store, a.agents.blobs, p.SHA256); err != nil {
		a.log.WarnContext(ctx, "remove a plugin's program", "sha256", p.SHA256, "err", err)
	}
	a.pushPlugins(ctx)
	w.WriteHeader(http.StatusNoContent)
}

// DevicePluginStateJSON is a plugin the device's ceiling allows, and what
// its agent did with it.
type DevicePluginStateJSON struct {
	Name string `json:"name"`
	// MaxClass is the highest class of its commands the device's ceiling
	// allows.
	MaxClass policy.Class `json:"max_class"`
	Version  string       `json:"version,omitempty"`
	SHA256   string       `json:"sha256,omitempty"`
	// Installed is set once the agent installed the program; Error says
	// why it did not.
	Installed bool   `json:"installed"`
	Error     string `json:"error,omitempty"`
	// Commands are the commands of the installed program's manifest, each
	// with whether the ceiling allows its class.
	Commands []DevicePluginCommandJSON `json:"commands"`
}

// DevicePluginCommandJSON is a command of a device's plugin.
type DevicePluginCommandJSON struct {
	plugins.CommandSpec
	Allowed bool `json:"allowed"`
}

// DeviceDevicePluginsJSON answers GET /api/v1/devices/{id}/plugins.
type DeviceDevicePluginsJSON struct {
	// Supported is whether the device's agent runs plugins (protocol
	// minor 14); an older one must be upgraded first.
	Supported bool `json:"supported"`
	// Connected is whether its agent reported the state of its plugins
	// to the hubs; OS and Arch are its platform, then.
	Connected bool                    `json:"connected"`
	OS        string                  `json:"os,omitempty"`
	Arch      string                  `json:"arch,omitempty"`
	Plugins   []DevicePluginStateJSON `json:"plugins"`
	// Decisions say, by class, what policy decides now for the caller's
	// commands: allow, confirm or deny.
	Decisions map[policy.Class]string `json:"decisions"`
}

// DevicePluginRunner runs the commands of devices' plugins through policy,
// for the API and MCP.
type DevicePluginRunner struct {
	Agents *Agents
	Store  *store.Store
	Policy interface {
		Do(ctx context.Context, req policy.Request, fn func(context.Context) error) error
	}
}

// Device is the plugins of device (an id, name or hostname): those its
// reported ceiling allows, with what its agent did with each.
func (p DevicePluginRunner) Device(ctx context.Context, device string) (DeviceDevicePluginsJSON, error) {
	out := DeviceDevicePluginsJSON{Plugins: []DevicePluginStateJSON{}}
	d, err := p.Store.Devices().Get(ctx, device)
	if err != nil {
		return out, err
	}
	var f Facts
	if len(d.Facts) > 0 {
		if err := json.Unmarshal(d.Facts, &f); err != nil {
			return out, fmt.Errorf("decode the facts of device %s: %w", d.ID, err)
		}
	}
	out.Supported = f.ProtocolMinor >= minPluginMinor
	st, err := p.Agents.PluginStatus(ctx, d.ID)
	if err != nil && !errors.Is(err, ErrAgentNotConnected) && !errors.Is(err, ErrStreamElsewhere) {
		return out, err
	}
	list, err := p.Store.DevicePlugins().List(ctx)
	if err != nil {
		return out, err
	}
	if st != nil {
		out.Connected, out.OS, out.Arch = true, st.GetOs(), st.GetArch()
	}
	var grants []PluginGrant
	if f.Ceiling != nil {
		grants = f.Ceiling.Plugins
	}
	for _, g := range grants {
		s := DevicePluginStateJSON{Name: g.Name, MaxClass: g.Class, Commands: []DevicePluginCommandJSON{}}
		if st == nil {
			s.Error = "the agent has not reported its plugins"
		}
		for _, ps := range st.GetPlugins() {
			if ps.GetName() != g.Name {
				continue
			}
			s.Version, s.SHA256, s.Error, s.Installed = ps.GetVersion(), ps.GetSha256(), ps.GetError(), ps.GetSha256() != ""
		}
		if st != nil && s.Version == "" && s.Error == "" && !s.Installed {
			s.Error = "no plugin of this name was uploaded"
		}
		if reg, ok := installedOf(list, st, g.Name); ok {
			if m, err := decodeManifest(reg); err == nil {
				for _, c := range m.Commands {
					s.Commands = append(s.Commands, DevicePluginCommandJSON{CommandSpec: c, Allowed: policy.Within(c.Class, g.Class)})
				}
			}
		}
		out.Plugins = append(out.Plugins, s)
	}
	return out, nil
}

// installedOf is the uploaded plugin name whose program the agent that
// reported st installed.
func installedOf(list []store.DevicePlugin, st *agentv1.PluginStatus, name string) (store.DevicePlugin, bool) {
	sum := ""
	for _, ps := range st.GetPlugins() {
		if ps.GetName() == name {
			sum = ps.GetSha256()
		}
	}
	if sum == "" {
		return store.DevicePlugin{}, false
	}
	i := slices.IndexFunc(list, func(p store.DevicePlugin) bool {
		return p.Name == name && p.OS == st.GetOs() && p.Arch == st.GetArch() && p.SHA256 == sum
	})
	if i < 0 {
		return store.DevicePlugin{}, false
	}
	return list[i], true
}

// Run runs a command of plugin name on device for actorKind/actorID,
// through policy: the action is device.plugin.command.<class>, of the class
// the uploaded manifest of the program the agent installed declares. A
// command it does not declare is denied, and audited as a denied dangerous
// command. The arguments are never audited: they may hold secrets.
func (p DevicePluginRunner) Run(ctx context.Context, actorKind, actorID, device, name string, req plugins.CommandRequest) (plugins.CommandResult, error) {
	if !policy.ValidPluginName(name) {
		return plugins.CommandResult{}, fmt.Errorf("%w: invalid plugin name", plugins.ErrBadRequest)
	}
	if err := plugins.CheckRequest(req); err != nil {
		return plugins.CommandResult{}, err
	}
	id, err := p.Agents.resolve(ctx, device)
	if err != nil {
		return plugins.CommandResult{}, err
	}
	st, err := p.Agents.PluginStatus(ctx, id)
	if err != nil {
		return plugins.CommandResult{}, err
	}
	list, err := p.Store.DevicePlugins().List(ctx)
	if err != nil {
		return plugins.CommandResult{}, err
	}
	reg, ok := installedOf(list, st, name)
	if !ok {
		return plugins.CommandResult{}, fmt.Errorf("device %s: plugin %s: %w", id, name, ErrPluginNotInstalled)
	}
	m, err := decodeManifest(reg)
	if err != nil {
		return plugins.CommandResult{}, err
	}
	i := slices.IndexFunc(m.Commands, func(c plugins.CommandSpec) bool { return c.Name == req.Command })
	action, class := policy.DevicePluginCommandDangerous, policy.Dangerous
	if i >= 0 {
		if a, ok := devicePluginActions[m.Commands[i].Class]; ok {
			action, class = a, m.Commands[i].Class
		}
	}
	preq := policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: action, Target: id,
		Detail: map[string]any{
			"plugin": name, "version": reg.Version, "sha256": reg.SHA256, "command": req.Command, "plugin_device": req.Device,
		},
		Precheck: func(ctx context.Context) error {
			if i < 0 {
				return fmt.Errorf("plugin %s declares no command %q: %w", name, req.Command, policy.ErrDenied)
			}
			return p.Agents.CheckPlugin(ctx, id, name, class)
		},
	}
	cmd := &agentv1.PluginCommand{Plugin: name, Sha256: reg.SHA256, Command: req.Command, Device: req.Device}
	if len(req.Args) > 0 {
		cmd.ArgsJson = string(req.Args)
	}
	var out plugins.CommandResult
	err = p.Policy.Do(ctx, preq, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, devicePluginTimeout+devicePluginGrace)
		defer cancel()
		res, err := p.Agents.Plugin(ctx, id, class, cmd, devicePluginTimeout)
		switch {
		case err != nil:
			return err
		case res.GetDenied():
			return fmt.Errorf("device %s: the agent refused: %s: %w", id, res.GetError(), policy.ErrBeyondCeiling)
		case !res.GetOk():
			return fmt.Errorf("%w: %s", plugins.ErrCommandFailed, res.GetError())
		}
		out.Output = res.GetOutput()
		return nil
	})
	return out, err
}

// DevicePluginsOf is Device, for MCP.
func (p DevicePluginRunner) DevicePluginsOf(ctx context.Context, device string) (any, error) {
	id, err := p.Agents.resolve(ctx, device)
	if err != nil {
		return nil, err
	}
	return p.Device(ctx, id)
}

func (a *api) devicePlugins() DevicePluginRunner {
	return DevicePluginRunner{Agents: a.agents, Store: a.store, Policy: a.policy}
}

// deviceDevicePlugins serves GET /api/v1/devices/{id}/plugins.
func (a *api) deviceDevicePlugins(w http.ResponseWriter, r *http.Request) {
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	out, err := a.devicePlugins().Device(r.Context(), d.ID)
	if err != nil {
		a.writeActionError(w, r, "read the device's plugins", err)
		return
	}
	out.Decisions = make(map[policy.Class]string, len(devicePluginActions))
	for class, action := range devicePluginActions {
		out.Decisions[class], _ = a.policy.Check(policy.Request{ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: action})
	}
	writeJSON(w, http.StatusOK, out)
}

// devicePluginCommand serves POST /api/v1/devices/{id}/plugins/{name}/commands
// with a plugins.CommandRequest: a command of the device's plugin, through
// policy. One policy holds for approval answers once it is decided.
func (a *api) devicePluginCommand(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req plugins.CommandRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPluginCommandBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be a command: {"command": "turn_on", "device": "lamp", "args": {}}`)
		return
	}
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	res, err := a.devicePlugins().Run(r.Context(), policy.ActorWeb, remoteHost(r), d.ID, r.PathValue("name"), req)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, res)
	case errors.Is(err, plugins.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, ErrPluginNotInstalled):
		writeError(w, http.StatusConflict, "not_installed", err.Error())
	case errors.Is(err, plugins.ErrCommandFailed):
		writeError(w, http.StatusBadGateway, "plugin_error", strings.TrimPrefix(err.Error(), plugins.ErrCommandFailed.Error()+": "))
	default:
		a.writeDockerError(w, r, err)
	}
}
