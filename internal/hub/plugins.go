// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxPluginCommandBody bounds POST /plugins/{name}/commands: the args are at
// most 16 KiB.
const maxPluginCommandBody = 32 << 10

// pluginRoutes registers the exec plugins API, behind the admin session.
// Without plugins there are no routes.
func (a *api) pluginRoutes(mux *http.ServeMux) {
	if a.plugins == nil {
		return
	}
	mux.Handle("GET /api/v1/plugins", a.auth(a.listPlugins))
	mux.Handle("POST /api/v1/plugins/{name}/commands", a.auth(a.pluginCommand))
}

func (a *api) listPlugins(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Plugins []plugins.Status `json:"plugins"`
	}{Plugins: a.plugins.Plugins()})
}

// pluginCommand runs a command of a plugin, through policy. One policy holds
// for approval answers once it is decided.
func (a *api) pluginCommand(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req plugins.CommandRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPluginCommandBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be a command: {"command": "turn_on", "device": "lamp", "args": {}}`)
		return
	}
	res, err := a.plugins.Command(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("name"), req)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, res)
	case errors.Is(err, plugins.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such plugin")
	case errors.Is(err, plugins.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, plugins.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the plugin is not running")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		writeError(w, http.StatusBadGateway, "plugin_error", err.Error())
	}
}
