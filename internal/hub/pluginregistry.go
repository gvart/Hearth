// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// The plugin registry (#75), the API's side: the plugins a signed index
// offers, those installed on this hub, and installing, updating and
// removing them, each through policy (plugin.registry.install and .update
// are dangerous and need the password again; .remove is safe) and audited.
// The hub installs only what it shows: the caller names the version and the
// SHA-256 it reviewed, and the hub refuses if the signed index now says
// otherwise.

// registryFetchTimeout bounds reading the index and a module for a request.
const registryFetchTimeout = time.Minute

// RegistryEntryJSON is a plugin as an index offers it, or as installed.
type RegistryEntryJSON struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Author      string `json:"author,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
	License     string `json:"license,omitempty"`
	Runtime     string `json:"runtime"`
	SHA256      string `json:"sha256"`
	// Digest names the whole entry: an install or update confirms it.
	Digest       string                `json:"digest"`
	Memory       int                   `json:"memory"`
	Capabilities []string              `json:"capabilities"`
	Commands     []plugins.CommandSpec `json:"commands"`
	// HTTPAllow are the hosts the plugin may reach: its only access
	// outside its sandbox.
	HTTPAllow []string `json:"http_allow"`
}

func registryEntryJSON(e plugins.IndexEntry) RegistryEntryJSON {
	commands := e.Commands
	if commands == nil {
		commands = []plugins.CommandSpec{}
	}
	caps := e.Capabilities
	if caps == nil {
		caps = []string{}
	}
	return RegistryEntryJSON{
		Name: e.Name, Version: e.Version, Description: e.Description, Author: e.Author, Homepage: e.Homepage,
		License: e.License, Runtime: e.Runtime, SHA256: e.SHA256, Digest: e.Digest(), Memory: e.MemoryMiB(),
		Capabilities: caps, Commands: commands, HTTPAllow: plugins.HTTPAllow(e.Host),
	}
}

// InstalledPluginJSON is a plugin installed from a registry.
type InstalledPluginJSON struct {
	RegistryEntryJSON
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installed_at"`
	InstalledBy string    `json:"installed_by"`
	// Update is the newer version the index offers, if any; never an older.
	Update *RegistryEntryJSON `json:"update,omitempty"`
	// Error is why the hub does not run it, if it does not.
	Error string `json:"error,omitempty"`
}

// PluginRegistryJSON answers GET /api/v1/plugin-registry.
type PluginRegistryJSON struct {
	// Enabled is false without a configured index: installed plugins are
	// still listed, run and removable.
	Enabled bool   `json:"enabled"`
	Source  string `json:"source,omitempty"`
	// Keys are the ids of the trusted index keys.
	Keys      []string              `json:"keys"`
	Installed []InstalledPluginJSON `json:"installed"`
	// Available are the newest version of each plugin the index offers.
	Available []RegistryEntryJSON `json:"available"`
	// IndexError is why the index could not be read or trusted.
	IndexError string `json:"index_error,omitempty"`
	// Decisions are what policy decides now for this session: install,
	// update and remove.
	Decisions map[string]string `json:"decisions"`
}

// RegistryChangeRequest is the body of an install or an update: the
// plugin, and the version, SHA-256 and entry digest the caller reviewed.
type RegistryChangeRequest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Digest  string `json:"digest"`
	// AllowDowngrade allows an update to an older version.
	AllowDowngrade bool `json:"allow_downgrade"`
}

func (a *api) pluginRegistryRoutes(mux *http.ServeMux) {
	if a.registryPlugins == nil {
		return
	}
	mux.Handle("GET /api/v1/plugin-registry", a.auth(a.getPluginRegistry))
	mux.Handle("POST /api/v1/plugin-registry/install", a.auth(a.installRegistryPlugin))
	mux.Handle("POST /api/v1/plugin-registry/update", a.auth(a.updateRegistryPlugin))
	mux.Handle("DELETE /api/v1/plugin-registry/{name}", a.auth(a.removeRegistryPlugin))
}

func (a *api) getPluginRegistry(w http.ResponseWriter, r *http.Request) {
	out := PluginRegistryJSON{Keys: []string{}, Installed: []InstalledPluginJSON{}, Available: []RegistryEntryJSON{}, Decisions: map[string]string{}}
	for k, action := range map[string]policy.Action{
		"install": policy.PluginRegistryInstall, "update": policy.PluginRegistryUpdate, "remove": policy.PluginRegistryRemove,
	} {
		out.Decisions[k], _ = a.policy.Check(policy.Request{ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: action})
	}
	installed, err := a.registryPlugins.Store.List()
	if err != nil && len(installed) == 0 {
		a.writeActionError(w, r, "list the installed plugins", err)
		return
	}
	var idx *plugins.Index
	if reg := a.pluginRegistry; reg != nil {
		out.Enabled, out.Source = true, reg.Source
		for _, k := range reg.Keys {
			out.Keys = append(out.Keys, plugins.KeyID(k))
		}
		ctx, cancel := context.WithTimeout(r.Context(), registryFetchTimeout)
		idx, err = reg.Fetch(ctx)
		cancel()
		if err != nil {
			out.IndexError = err.Error()
			idx = nil
		}
	}
	if idx != nil {
		for _, e := range idx.Newest() {
			out.Available = append(out.Available, registryEntryJSON(e))
		}
	}
	errs := a.registryPlugins.Errors()
	for _, in := range installed {
		j := InstalledPluginJSON{
			RegistryEntryJSON: registryEntryJSON(in.Entry), Source: in.Source,
			InstalledAt: in.InstalledAt, InstalledBy: in.InstalledBy, Error: errs[in.Entry.Name],
		}
		if idx != nil {
			if e, ok := idx.Latest(in.Entry.Name); ok && plugins.CompareVersions(e.Version, in.Entry.Version) > 0 {
				u := registryEntryJSON(e)
				j.Update = &u
			}
		}
		out.Installed = append(out.Installed, j)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) installRegistryPlugin(w http.ResponseWriter, r *http.Request) {
	a.changeRegistryPlugin(w, r, policy.PluginRegistryInstall)
}

func (a *api) updateRegistryPlugin(w http.ResponseWriter, r *http.Request) {
	a.changeRegistryPlugin(w, r, policy.PluginRegistryUpdate)
}

// changeRegistryPlugin installs or updates a plugin: refused, and audited,
// unless the session entered the password again; then the signed index is
// read again, the entry checked against what the caller reviewed, the
// module downloaded and checked against its SHA-256, and only then is the
// change decided by policy and written.
func (a *api) changeRegistryPlugin(w http.ResponseWriter, r *http.Request, action policy.Action) {
	ctx := r.Context()
	var req RegistryChangeRequest
	if !decodeJSON(w, r, 4<<10, &req, `{"name": "...", "version": "...", "sha256": "...", "digest": "..."}`) {
		return
	}
	actor := func(p policy.Request) policy.Request {
		p.ActorKind, p.ActorID, p.Precheck = policy.ActorWeb, remoteHost(r), a.recentAuth(r)
		return p
	}
	// Refused, and audited, before anything is fetched.
	if a.reauthUntil(r).IsZero() {
		err := a.policy.Do(ctx, actor(policy.Request{Action: action, Target: req.Name}), func(context.Context) error { return nil })
		a.writeActionError(w, r, "change the plugin", err)
		return
	}
	if req.Name == "" || !plugins.ValidVersion(req.Version) || !plugins.ValidSHA256(req.SHA256) || !plugins.ValidSHA256(req.Digest) {
		writeError(w, http.StatusBadRequest, "bad_request", "name, and the version, sha256 and digest reviewed are required")
		return
	}
	if a.pluginRegistry == nil {
		writeError(w, http.StatusConflict, "registry_off", plugins.ErrRegistryOff.Error()+": start the hub with --plugin-index and --plugin-index-key")
		return
	}
	if a.plugins != nil && a.plugins.Configured(req.Name) {
		writeError(w, http.StatusConflict, "conflict", "a plugin of that name runs from the hub's --plugin flags")
		return
	}
	fctx, cancel := context.WithTimeout(ctx, registryFetchTimeout)
	defer cancel()
	idx, err := a.pluginRegistry.Fetch(fctx)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	st := a.registryPlugins.Store
	var c plugins.Change
	if action == policy.PluginRegistryInstall {
		c, err = plugins.PlanInstall(idx, a.pluginRegistry.Source, st, req.Name, req.Version)
	} else {
		c, err = plugins.PlanUpdate(idx, a.pluginRegistry.Source, st, req.Name, req.Version, req.AllowDowngrade)
	}
	if err == nil {
		err = c.Confirmed(req.Version, req.SHA256, req.Digest)
	}
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	module, err := a.pluginRegistry.Download(fctx, c.Entry)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	by := policy.ActorWeb + "/" + remoteHost(r)
	if err := a.policy.Do(ctx, actor(c.Request()), func(context.Context) error {
		return st.Put(c.Entry, module, c.Source, by, a.now())
	}); err != nil {
		a.writeActionError(w, r, "install the plugin", err)
		return
	}
	a.log.InfoContext(ctx, "registry plugin installed", "plugin", c.Entry.Name, "version", c.Entry.Version, "sha256", c.Entry.SHA256)
	a.registryPlugins.Sync(context.WithoutCancel(ctx))
	status := http.StatusOK
	if action == policy.PluginRegistryInstall {
		status = http.StatusCreated
	}
	writeJSON(w, status, registryEntryJSON(c.Entry))
}

func (a *api) removeRegistryPlugin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	st := a.registryPlugins.Store
	in, ok, err := st.Get(name)
	if err != nil {
		a.writeActionError(w, r, "read the installed plugin", err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no plugin of that name is installed from a registry")
		return
	}
	req := plugins.RemoveRequest(in)
	req.ActorKind, req.ActorID = policy.ActorWeb, remoteHost(r)
	if err := a.policy.Do(ctx, req, func(context.Context) error { return st.Remove(name) }); err != nil {
		a.writeActionError(w, r, "remove the plugin", err)
		return
	}
	a.registryPlugins.Sync(context.WithoutCancel(ctx))
	w.WriteHeader(http.StatusNoContent)
}

// registryCodes are the registry errors the caller can act on, with their
// status and code.
var registryCodes = []struct {
	err    error
	status int
	code   string
}{
	{plugins.ErrIndexSignature, http.StatusBadGateway, "index_untrusted"},
	{plugins.ErrPinMismatch, http.StatusBadGateway, "pin_mismatch"},
	{plugins.ErrIndexChanged, http.StatusConflict, "index_changed"},
	{plugins.ErrModuleChanged, http.StatusConflict, "module_changed"},
	{plugins.ErrNotInIndex, http.StatusNotFound, "not_in_index"},
	{plugins.ErrInstalled, http.StatusConflict, "installed"},
	{plugins.ErrNotInstalled, http.StatusNotFound, "not_installed"},
	{plugins.ErrDowngrade, http.StatusConflict, "downgrade"},
	{plugins.ErrUpToDate, http.StatusConflict, "up_to_date"},
}

// writeRegistryError answers a registry error.
func writeRegistryError(w http.ResponseWriter, err error) {
	for _, c := range registryCodes {
		if errors.Is(err, c.err) {
			writeError(w, c.status, c.code, err.Error())
			return
		}
	}
	writeError(w, http.StatusBadGateway, "registry_unavailable", err.Error())
}
