// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/telemetry"
)

// TelemetryJSON is the admin's answer to "Share anonymous usage stats?"; see
// docs/telemetry.md.
type TelemetryJSON struct {
	// Answered is false until the admin answers: the web UI then asks.
	Answered bool `json:"answered"`
	Enabled  bool `json:"enabled"`
	// DisabledByEnv is HEARTH_TELEMETRY=off (or --telemetry=off): nothing is
	// sent whatever the answer, and the web UI does not ask.
	DisabledByEnv bool `json:"disabled_by_env"`
}

func (a *api) telemetryRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/telemetry", a.auth(a.getTelemetry))
	mux.Handle("PUT /api/v1/telemetry", a.auth(a.setTelemetry))
}

func (a *api) getTelemetry(w http.ResponseWriter, r *http.Request) {
	set, err := a.store.Telemetry().Get(r.Context())
	if err != nil {
		a.log.ErrorContext(r.Context(), "get telemetry", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot read the telemetry setting")
		return
	}
	writeJSON(w, http.StatusOK, TelemetryJSON{Answered: set.Answered, Enabled: set.Enabled, DisabledByEnv: a.telemetryOff})
}

// setTelemetry stores the admin's answer, through policy. Opting in makes a
// new random install ID; opting out forgets it.
func (a *api) setTelemetry(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil || body.Enabled == nil {
		writeError(w, http.StatusBadRequest, "bad_request", `want {"enabled": true|false}`)
		return
	}
	if a.telemetryOff {
		writeError(w, http.StatusConflict, "telemetry_disabled",
			"telemetry is turned off on the hub (HEARTH_TELEMETRY=off or --telemetry=off)")
		return
	}
	enabled := *body.Enabled
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.TelemetrySet, Target: "telemetry",
		Detail: map[string]any{"enabled": enabled},
	}, func(ctx context.Context) error {
		id := ""
		if enabled {
			id = telemetry.NewInstallID()
		}
		return a.store.Telemetry().Set(ctx, enabled, id, a.now())
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, TelemetryJSON{Answered: true, Enabled: enabled})
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates telemetry: run `hearth cluster migrate` first")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), "set telemetry", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot store the telemetry setting")
	}
}
