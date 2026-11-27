// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/gvart/hearth/internal/integrations/opnsense"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxOPNsenseBody bounds POST /opnsense/firewalls: a URL, an API key and a
// fingerprint.
const maxOPNsenseBody = 4 << 10

// opnsenseRoutes registers the OPNsense API, behind the admin session. Without
// a manager there are no routes.
func (a *api) opnsenseRoutes(mux *http.ServeMux) {
	if a.opnsense == nil {
		return
	}
	mux.Handle("GET /api/v1/opnsense/firewalls", a.auth(a.listOPNsenseFirewalls))
	mux.Handle("POST /api/v1/opnsense/firewalls", a.auth(a.addOPNsenseFirewall))
	mux.Handle("GET /api/v1/opnsense/firewalls/{id}", a.auth(a.getOPNsenseFirewall))
	mux.Handle("DELETE /api/v1/opnsense/firewalls/{id}", a.auth(a.removeOPNsenseFirewall))
	mux.Handle("POST /api/v1/opnsense/firewalls/{id}/restart-unbound", a.auth(a.opnsenseRestartUnbound))
}

func (a *api) listOPNsenseFirewalls(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Firewalls []opnsense.FirewallInfo `json:"firewalls"`
	}{Firewalls: a.opnsense.Firewalls()})
}

func (a *api) getOPNsenseFirewall(w http.ResponseWriter, r *http.Request) {
	snap, err := a.opnsense.Snapshot(r.PathValue("id"))
	if err != nil {
		a.writeOPNsenseError(w, r, "get opnsense firewall", err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (a *api) addOPNsenseFirewall(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req opnsense.AddRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOPNsenseBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"name": "...", "url": "...", "key": "...", "secret": "..."}`)
		return
	}
	info, err := a.opnsense.Add(r.Context(), remoteHost(r), req)
	if err != nil {
		a.writeOPNsenseError(w, r, "add opnsense firewall", err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (a *api) removeOPNsenseFirewall(w http.ResponseWriter, r *http.Request) {
	if err := a.opnsense.Remove(r.Context(), remoteHost(r), r.PathValue("id")); err != nil {
		a.writeOPNsenseError(w, r, "remove opnsense firewall", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// opnsenseRestartUnbound restarts Unbound on a firewall: dangerous, so the session
// must have entered the admin password again lately.
func (a *api) opnsenseRestartUnbound(w http.ResponseWriter, r *http.Request) {
	res, err := a.opnsense.RestartDNS(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), a.recentAuth(r))
	if err != nil {
		a.writeOPNsenseError(w, r, "opnsense restart unbound", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// writeOPNsenseError answers a failed OPNsense API call. No error carries the
// API key or secret: the manager's never quote them.
func (a *api) writeOPNsenseError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, opnsense.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such firewall")
	case errors.Is(err, opnsense.ErrBadConnection), errors.Is(err, opnsense.ErrBadName):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, opnsense.ErrNameTaken):
		writeError(w, http.StatusConflict, "conflict", "a firewall with that name exists")
	case errors.Is(err, opnsense.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates OPNsense firewalls: upgrade every hub of the cluster first")
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
		writeError(w, http.StatusBadGateway, "opnsense_error", err.Error())
	}
}
