// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/gvart/hearth/internal/integrations/proxmox"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxProxmoxBody bounds POST /proxmox/servers: a CA certificate is a few KiB.
const maxProxmoxBody = 64 << 10

// proxmoxRoutes registers the Proxmox API, behind the admin session. Without
// a manager there are no routes.
func (a *api) proxmoxRoutes(mux *http.ServeMux) {
	if a.proxmox == nil {
		return
	}
	mux.Handle("GET /api/v1/proxmox/servers", a.auth(a.listProxmoxServers))
	mux.Handle("POST /api/v1/proxmox/servers", a.auth(a.addProxmoxServer))
	mux.Handle("GET /api/v1/proxmox/servers/{id}", a.auth(a.getProxmoxServer))
	mux.Handle("DELETE /api/v1/proxmox/servers/{id}", a.auth(a.removeProxmoxServer))
	mux.Handle("POST /api/v1/proxmox/servers/{id}/actions", a.auth(a.proxmoxAction))
}

func (a *api) listProxmoxServers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Servers []proxmox.ServerInfo `json:"servers"`
	}{Servers: a.proxmox.Servers()})
}

func (a *api) getProxmoxServer(w http.ResponseWriter, r *http.Request) {
	snap, err := a.proxmox.Snapshot(r.PathValue("id"))
	if err != nil {
		a.writeProxmoxError(w, r, "get proxmox server", err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (a *api) addProxmoxServer(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req proxmox.AddRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProxmoxBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"name": "...", "url": "...", "token": "...", ...}`)
		return
	}
	info, err := a.proxmox.Add(r.Context(), remoteHost(r), req)
	if err != nil {
		a.writeProxmoxError(w, r, "add proxmox server", err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (a *api) removeProxmoxServer(w http.ResponseWriter, r *http.Request) {
	if err := a.proxmox.Remove(r.Context(), remoteHost(r), r.PathValue("id")); err != nil {
		a.writeProxmoxError(w, r, "remove proxmox server", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// proxmoxAction starts, stops or reboots a guest. An action policy holds for
// approval answers once it is decided.
func (a *api) proxmoxAction(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req proxmox.ActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be an action: {"action": "start", "vmid": 100}`)
		return
	}
	res, err := a.proxmox.Act(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), req)
	if err != nil {
		a.writeProxmoxError(w, r, "proxmox action", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// writeProxmoxError answers a failed Proxmox API call.
func (a *api) writeProxmoxError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, proxmox.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such server")
	case errors.Is(err, proxmox.ErrGuestNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such guest on this server")
	case errors.Is(err, proxmox.ErrGuestChanged):
		writeError(w, http.StatusConflict, "guest_changed", err.Error())
	case errors.Is(err, proxmox.ErrBadConnection), errors.Is(err, proxmox.ErrBadName), errors.Is(err, proxmox.ErrBadAction):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, proxmox.ErrNameTaken):
		writeError(w, http.StatusConflict, "conflict", "a server with that name exists")
	case errors.Is(err, proxmox.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates Proxmox servers: upgrade every hub of the cluster first")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusBadGateway, "proxmox_error", err.Error())
	}
}
