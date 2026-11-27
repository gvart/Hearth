// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/gvart/hearth/internal/integrations/openwrt"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxOpenWrtBody bounds POST /openwrt/routers: a URL, a login and a
// fingerprint.
const maxOpenWrtBody = 4 << 10

// openwrtRoutes registers the OpenWrt API, behind the admin session. Without
// a manager there are no routes.
func (a *api) openwrtRoutes(mux *http.ServeMux) {
	if a.openwrt == nil {
		return
	}
	mux.Handle("GET /api/v1/openwrt/routers", a.auth(a.listOpenWrtRouters))
	mux.Handle("POST /api/v1/openwrt/routers", a.auth(a.addOpenWrtRouter))
	mux.Handle("GET /api/v1/openwrt/routers/{id}", a.auth(a.getOpenWrtRouter))
	mux.Handle("DELETE /api/v1/openwrt/routers/{id}", a.auth(a.removeOpenWrtRouter))
	mux.Handle("POST /api/v1/openwrt/routers/{id}/restart-dnsmasq", a.auth(a.openwrtRestartDNS))
}

func (a *api) listOpenWrtRouters(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Routers []openwrt.RouterInfo `json:"routers"`
	}{Routers: a.openwrt.Routers()})
}

func (a *api) getOpenWrtRouter(w http.ResponseWriter, r *http.Request) {
	snap, err := a.openwrt.Snapshot(r.PathValue("id"))
	if err != nil {
		a.writeOpenWrtError(w, r, "get openwrt router", err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (a *api) addOpenWrtRouter(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req openwrt.AddRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOpenWrtBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"name": "...", "url": "...", "username": "...", "password": "..."}`)
		return
	}
	info, err := a.openwrt.Add(r.Context(), remoteHost(r), req)
	if err != nil {
		a.writeOpenWrtError(w, r, "add openwrt router", err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (a *api) removeOpenWrtRouter(w http.ResponseWriter, r *http.Request) {
	if err := a.openwrt.Remove(r.Context(), remoteHost(r), r.PathValue("id")); err != nil {
		a.writeOpenWrtError(w, r, "remove openwrt router", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// openwrtRestartDNS restarts dnsmasq on a router: dangerous, so the session
// must have entered the admin password again lately.
func (a *api) openwrtRestartDNS(w http.ResponseWriter, r *http.Request) {
	res, err := a.openwrt.RestartDNS(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), a.recentAuth(r))
	if err != nil {
		a.writeOpenWrtError(w, r, "openwrt restart dnsmasq", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// writeOpenWrtError answers a failed OpenWrt API call. No error carries the
// password: the manager's never quote it.
func (a *api) writeOpenWrtError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, openwrt.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such router")
	case errors.Is(err, openwrt.ErrBadConnection), errors.Is(err, openwrt.ErrBadName):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, openwrt.ErrNameTaken):
		writeError(w, http.StatusConflict, "conflict", "a router with that name exists")
	case errors.Is(err, openwrt.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates OpenWrt routers: upgrade every hub of the cluster first")
	// errReauthRequired wraps policy.ErrDenied: it goes first, so the web UI
	// asks for the password.
	case errors.Is(err, errReauthRequired):
		writeError(w, http.StatusForbidden, "reauth_required", "enter the admin password again to do this")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusBadGateway, "openwrt_error", err.Error())
	}
}
