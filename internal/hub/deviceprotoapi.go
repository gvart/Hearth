// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// maxProtocolCommandBody bounds POST /devices/{id}/commands: a command name
// and its params.
const maxProtocolCommandBody = 8 << 10

// deviceProtocolRoutes registers the Device Protocol's command endpoint,
// behind the admin session. Without a handler there is none.
func (a *api) deviceProtocolRoutes(mux *http.ServeMux) {
	if a.protocol == nil {
		return
	}
	mux.Handle("POST /api/v1/devices/{id}/commands", a.auth(a.deviceProtocolCommand))
}

// deviceProtocolCommand sends a Device Protocol device a command it
// announced and answers its result: {"command": "relay.set", "params": {...}}.
// It is the policy action device.command, dangerous: the session must have
// entered the admin password again within ReauthTTL.
func (a *api) deviceProtocolCommand(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var req CommandRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtocolCommandBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be a command: {"command": "relay.set", "params": {"on": true}}`)
		return
	}
	res, err := a.protocol.Command(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), req, a.recentAuth(r))
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, res)
	case errors.Is(err, ErrProtocolDeviceNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such device protocol device")
	case errors.Is(err, ErrProtocolUnknownCommand), errors.Is(err, ErrProtocolBadCommand):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	// errReauthRequired wraps policy.ErrDenied: it goes first, so the web UI
	// asks for the password.
	case errors.Is(err, errReauthRequired):
		writeError(w, http.StatusForbidden, "reauth_required", "enter the admin password again to do this")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, ErrProtocolUnavailable):
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	case errors.Is(err, ErrProtocolTimeout):
		writeError(w, http.StatusGatewayTimeout, "timeout", err.Error())
	case errors.Is(err, ErrProtocolFailed):
		writeJSON(w, http.StatusBadGateway, res)
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), "device protocol command", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot send the command")
	}
}
