// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/gvart/hearth/internal/integrations/unifi"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxUniFiBody bounds POST /unifi/controllers: a URL, a site, a login or an
// API key and a fingerprint.
const maxUniFiBody = 4 << 10

// unifiRoutes registers the UniFi API, behind the admin session. Without a
// manager there are no routes.
func (a *api) unifiRoutes(mux *http.ServeMux) {
	if a.unifi == nil {
		return
	}
	mux.Handle("GET /api/v1/unifi/controllers", a.auth(a.listUniFiControllers))
	mux.Handle("POST /api/v1/unifi/controllers", a.auth(a.addUniFiController))
	mux.Handle("GET /api/v1/unifi/controllers/{id}", a.auth(a.getUniFiController))
	mux.Handle("DELETE /api/v1/unifi/controllers/{id}", a.auth(a.removeUniFiController))
	mux.Handle("POST /api/v1/unifi/controllers/{id}/devices/{mac}/restart", a.auth(a.unifiRestartAP))
}

func (a *api) listUniFiControllers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Controllers []unifi.ControllerInfo `json:"controllers"`
	}{Controllers: a.unifi.Controllers()})
}

func (a *api) getUniFiController(w http.ResponseWriter, r *http.Request) {
	snap, err := a.unifi.Snapshot(r.PathValue("id"))
	if err != nil {
		a.writeUniFiError(w, r, "get unifi controller", err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (a *api) addUniFiController(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req unifi.AddRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUniFiBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request",
			`body must be {"name": "...", "url": "...", "kind": "unifi_os"|"classic", "api_key": "..." or "username"/"password"}`)
		return
	}
	info, err := a.unifi.Add(r.Context(), remoteHost(r), req)
	if err != nil {
		a.writeUniFiError(w, r, "add unifi controller", err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (a *api) removeUniFiController(w http.ResponseWriter, r *http.Request) {
	if err := a.unifi.Remove(r.Context(), remoteHost(r), r.PathValue("id")); err != nil {
		a.writeUniFiError(w, r, "remove unifi controller", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// unifiRestartAP restarts an access point: dangerous, so the session must
// have entered the admin password again lately.
func (a *api) unifiRestartAP(w http.ResponseWriter, r *http.Request) {
	res, err := a.unifi.RestartAP(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), r.PathValue("mac"), a.recentAuth(r))
	if err != nil {
		a.writeUniFiError(w, r, "unifi restart ap", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// writeUniFiError answers a failed UniFi API call. No error carries a
// credential: the manager's never quote one.
func (a *api) writeUniFiError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, unifi.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such controller")
	case errors.Is(err, unifi.ErrNoSuchAP):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, unifi.ErrBadConnection), errors.Is(err, unifi.ErrBadName):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, unifi.ErrNameTaken):
		writeError(w, http.StatusConflict, "conflict", "a controller with that name exists")
	case errors.Is(err, unifi.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates UniFi controllers: upgrade every hub of the cluster first")
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
		writeError(w, http.StatusBadGateway, "unifi_error", err.Error())
	}
}
