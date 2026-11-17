// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

func TestAPICreateToken(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))

	start := time.Now()
	resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"ttl":"30m","labels":{"room":"attic"}}`, c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body %s", resp.StatusCode, resp.body)
	}
	got := decode[TokenJSON](t, resp)
	tok, err := pki.ParseToken(got.Token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if d := got.ExpiresAt.Sub(start); d < 29*time.Minute || d > 31*time.Minute {
		t.Errorf("expires_at %s is %s from now, want ~30m", got.ExpiresAt, d)
	}
	// The fixture serves on 127.0.0.1, which the hub certificate covers.
	port := strings.TrimPrefix(f.srv.URL, "http://127.0.0.1:")
	wantInstall := "curl -fsSL http://127.0.0.1:" + port + "/install.sh | HEARTH_TOKEN=" + got.Token + " sh -s -- --hub https://127.0.0.1:7443"
	if got.InstallCommand != wantInstall {
		t.Errorf("install_command = %q, want %q", got.InstallCommand, wantInstall)
	}
	// Everything after `sh -s --` lands in the argv of the user's sh, which
	// any local user can read with ps: the token must not be there.
	_, args, ok := strings.Cut(got.InstallCommand, " sh -s --")
	if !ok || strings.Contains(args, got.Token) || strings.Contains(args, "--token") {
		t.Errorf("install_command %q passes the token in the argv of sh", got.InstallCommand)
	}
	if want := "hearth agent join https://127.0.0.1:7443 " + got.Token; got.JoinCommand != want {
		t.Errorf("join_command = %q, want %q", got.JoinCommand, want)
	}

	// The token is stored, single use, and carries the labels.
	labels, err := f.st.Tokens().Consume(t.Context(), tok.Secret, time.Now())
	if err != nil || labels["room"] != "attic" {
		t.Fatalf("consume = %v, %v", labels, err)
	}
	if _, err := f.st.Tokens().Consume(t.Context(), tok.Secret, time.Now()); err == nil {
		t.Error("token consumed twice")
	}

	entries, err := f.st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != string(policy.TokenCreate) {
			continue
		}
		found = true
		if e.ActorKind != policy.ActorWeb || e.ActorID != "127.0.0.1" || e.Decision != policy.Allow || e.Result != "ok" {
			t.Errorf("audit = %+v", e)
		}
		var detail map[string]any
		if err := json.Unmarshal(e.Detail, &detail); err != nil || detail["ttl"] != "30m0s" {
			t.Errorf("audit detail = %s (%v)", e.Detail, err)
		}
		if strings.Contains(string(e.Detail), tok.Secret) {
			t.Error("token secret in audit detail")
		}
	}
	if !found {
		t.Error("no token.create audit entry")
	}
	if logs := f.logs.String(); strings.Contains(logs, tok.Secret) {
		t.Errorf("token secret in logs:\n%s", logs)
	}
}

func TestAPICreateTokenDefaults(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))
	for _, body := range []string{`{}`, `{"ttl":""}`} {
		start := time.Now()
		resp := f.do(t, http.MethodPost, "/api/v1/tokens", body, c)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: status = %d, body %s", body, resp.StatusCode, resp.body)
		}
		if d := decode[TokenJSON](t, resp).ExpiresAt.Sub(start); d < 14*time.Minute || d > 16*time.Minute {
			t.Errorf("%s: default ttl = %s, want ~15m", body, d)
		}
	}
}

func TestAPICreateTokenRejects(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))
	manyLabels := map[string]string{}
	for i := range maxTokenLabels + 1 {
		manyLabels[strings.Repeat("k", i+1)] = "v"
	}
	tooMany, _ := json.Marshal(map[string]any{"labels": manyLabels})

	tests := []struct {
		name, contentType, body string
		wantStatus              int
	}{
		{"form content type", "application/x-www-form-urlencoded", `{}`, http.StatusUnsupportedMediaType},
		{"no body or content type", "application/json", ``, http.StatusUnsupportedMediaType},
		{"empty JSON body", "application/json", ` `, http.StatusBadRequest},
		{"not JSON", "application/json", `ttl=15m`, http.StatusBadRequest},
		{"unknown field", "application/json", `{"ttl":"15m","admin":true}`, http.StatusBadRequest},
		{"ttl not a duration", "application/json", `{"ttl":"soon"}`, http.StatusBadRequest},
		{"ttl a number", "application/json", `{"ttl":900}`, http.StatusBadRequest},
		{"ttl zero", "application/json", `{"ttl":"0s"}`, http.StatusBadRequest},
		{"ttl negative", "application/json", `{"ttl":"-5m"}`, http.StatusBadRequest},
		{"ttl too long", "application/json", `{"ttl":"25h"}`, http.StatusBadRequest},
		{"empty label key", "application/json", `{"labels":{"":"x"}}`, http.StatusBadRequest},
		{"label value too long", "application/json", `{"labels":{"k":"` + strings.Repeat("v", 129) + `"}}`, http.StatusBadRequest},
		{"too many labels", "application/json", string(tooMany), http.StatusBadRequest},
		{"body too large", "application/json", `{"ttl":"` + strings.Repeat(" ", maxTokenBody) + `"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := f.send(t, http.MethodPost, "/api/v1/tokens", tt.contentType, tt.body, c)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tt.wantStatus, resp.body)
			}
			if e := decode[ErrorJSON](t, resp); e.Code != "bad_request" {
				t.Errorf("error = %+v", e)
			}
		})
	}
	// Nothing reached policy, so nothing was created or audited.
	entries, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == string(policy.TokenCreate) {
			t.Errorf("rejected request audited: %+v", e)
		}
	}
}

func TestCommandHosts(t *testing.T) {
	a := &api{agentHosts: []string{"hub.lan", "localhost", "127.0.0.1", "::1"}}
	tests := []struct {
		reqHost, wantHTTP, wantAgent string
		ok                           bool
	}{
		{"hub.lan:7080", "hub.lan:7080", "hub.lan", true},
		{"HUB.lan:7080", "HUB.lan:7080", "HUB.lan", true},
		{"localhost", "localhost", "localhost", true},
		{"[::1]:7080", "[::1]:7080", "::1", true},
		// Not in the certificate: agents would fail to verify it.
		{"192.168.1.20:7080", "192.168.1.20:7080", "hub.lan", true},
		{"nas.example.com", "nas.example.com", "hub.lan", true},
		{"", "", "", false},
		{"evil;rm -rf /:7080", "", "", false},
		{"$(id).lan:7080", "", "", false},
		{"hub.lan:70x0", "", "", false},
		{"hub.lan:0", "", "", false},
		{"hub.lan:99999", "", "", false},
		{"hub.lan:07080", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.reqHost, func(t *testing.T) {
			httpHost, agentHost, ok := a.commandHosts(tt.reqHost)
			if ok != tt.ok || httpHost != tt.wantHTTP || agentHost != tt.wantAgent {
				t.Errorf("commandHosts(%q) = %q, %q, %v; want %q, %q, %v",
					tt.reqHost, httpHost, agentHost, ok, tt.wantHTTP, tt.wantAgent, tt.ok)
			}
		})
	}
}
