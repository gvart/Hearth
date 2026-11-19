// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

func TestAPITelemetry(t *testing.T) {
	f := newAPIFixture(t, true)
	ctx := t.Context()

	// Without a session nothing is read or stored.
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if resp := f.do(t, m, "/api/v1/telemetry", `{"enabled":true}`, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s without a session: %d, want 401", m, resp.StatusCode)
		}
	}
	if set, _ := f.st.Telemetry().Get(ctx); set.Answered {
		t.Fatalf("stored %+v without a session", set)
	}

	cookie := sessionCookie(t, f.login(t, testPassword))
	if got := decode[TelemetryJSON](t, f.do(t, http.MethodGet, "/api/v1/telemetry", "", cookie)); got != (TelemetryJSON{}) {
		t.Errorf("before an answer: %+v, want unanswered", got)
	}

	for _, tt := range []struct {
		name, body string
		status     int
		want       TelemetryJSON
	}{
		{"no body", ``, http.StatusBadRequest, TelemetryJSON{}},
		{"no field", `{}`, http.StatusBadRequest, TelemetryJSON{}},
		{"yes", `{"enabled":true}`, http.StatusOK, TelemetryJSON{Answered: true, Enabled: true}},
		{"no", `{"enabled":false}`, http.StatusOK, TelemetryJSON{Answered: true}},
		{"yes again", `{"enabled":true}`, http.StatusOK, TelemetryJSON{Answered: true, Enabled: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before, _ := f.st.Telemetry().Get(ctx)
			resp := f.do(t, http.MethodPut, "/api/v1/telemetry", tt.body, cookie)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d (%s)", resp.StatusCode, tt.status, resp.body)
			}
			if tt.status != http.StatusOK {
				return
			}
			if got := decode[TelemetryJSON](t, f.do(t, http.MethodGet, "/api/v1/telemetry", "", cookie)); got != tt.want {
				t.Errorf("GET = %+v, want %+v", got, tt.want)
			}
			set, _ := f.st.Telemetry().Get(ctx)
			if set.Enabled != (set.InstallID != "") {
				t.Errorf("stored %+v: an install ID only while on", set)
			}
			if set.Enabled && set.InstallID == before.InstallID {
				t.Errorf("opting in kept install ID %q, want a new one", set.InstallID)
			}
		})
	}

	// Every answer is audited as telemetry.set, by the web session, without
	// the install ID.
	set, _ := f.st.Telemetry().Get(ctx)
	entries, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		if e.Action != string(policy.TelemetrySet) {
			continue
		}
		if e.ActorKind != policy.ActorWeb || e.Decision != policy.Allow || e.Result != "ok" {
			t.Errorf("audit entry %+v, want an allowed web action", e)
		}
		if strings.Contains(string(e.Detail), set.InstallID) {
			t.Errorf("audit detail %s holds the install ID", e.Detail)
		}
		var d struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.Unmarshal(e.Detail, &d)
		if d.Enabled {
			got = append(got, "yes")
		} else {
			got = append(got, "no")
		}
	}
	slices.Sort(got)
	if want := []string{"no", "yes", "yes"}; !slices.Equal(got, want) {
		t.Errorf("audited answers %v, want %v", got, want)
	}
}

// With HEARTH_TELEMETRY=off the UI is told so and the answer cannot change.
func TestAPITelemetryOff(t *testing.T) {
	f := newAPIFixture(t, true, func(c *Config) { c.TelemetryOff = true })
	cookie := sessionCookie(t, f.login(t, testPassword))
	if got := decode[TelemetryJSON](t, f.do(t, http.MethodGet, "/api/v1/telemetry", "", cookie)); !got.DisabledByEnv {
		t.Errorf("GET = %+v, want disabled_by_env", got)
	}
	if resp := f.do(t, http.MethodPut, "/api/v1/telemetry", `{"enabled":true}`, cookie); resp.StatusCode != http.StatusConflict {
		t.Errorf("PUT: %d, want 409", resp.StatusCode)
	}
	if set, _ := f.st.Telemetry().Get(t.Context()); set.Answered {
		t.Errorf("stored %+v with telemetry off", set)
	}
}

// A policy that denies safe web actions denies the answer, and audits it.
func TestAPITelemetryDenied(t *testing.T) {
	f := newAPIFixture(t, true)
	f.api.policy = policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), policy.Config{
		Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Safe: policy.ModeDeny}},
	})
	cookie := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodPut, "/api/v1/telemetry", `{"enabled":true}`, cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT: %d, want 403 (%s)", resp.StatusCode, resp.body)
	}
	if set, _ := f.st.Telemetry().Get(t.Context()); set.Answered {
		t.Errorf("stored %+v though denied", set)
	}
	entries, _ := f.st.Audit().List(t.Context(), 100)
	for _, e := range entries {
		if e.Action == string(policy.TelemetrySet) && e.Decision == policy.Deny {
			return
		}
	}
	t.Error("no deny audit entry for telemetry.set")
}
