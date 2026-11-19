// SPDX-License-Identifier: AGPL-3.0-only

package beszel_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/beszel"
	"github.com/gvart/hearth/internal/integrations/beszel/beszelmock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func serve(t *testing.T, m *beszelmock.Server) string {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv.URL
}

func newClient(t *testing.T, m *beszelmock.Server, password string, hc *http.Client) *beszel.Client {
	t.Helper()
	c, err := beszel.New(serve(t, m)+"/", beszelmock.Email, password, hc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSystems(t *testing.T) {
	m := beszelmock.New(beszelmock.Email, beszelmock.Password)
	got, err := newClient(t, m, beszelmock.Password, nil).Systems(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("systems = %+v; want 3", got)
	}
	want := beszel.System{
		ID: "a1b2c3d4e5f6g7h", Name: "pi5", Host: "192.168.20.171", Status: beszel.StatusUp,
		CPU: 7.5, Memory: 41.2, Disk: 63, Uptime: 864000, AgentVersion: "0.18.0",
	}
	if got[0] != want {
		t.Errorf("system = %+v; want %+v", got[0], want)
	}
	if got[2].Status != beszel.StatusDown {
		t.Errorf("down system = %+v", got[2])
	}
}

func TestSystemsPages(t *testing.T) {
	m := beszelmock.New(beszelmock.Email, beszelmock.Password)
	var many []map[string]any
	for i := range 7 {
		s := beszelmock.Systems()[0]
		s["id"], s["name"] = fmt.Sprintf("id%013d", i), fmt.Sprintf("host-%d", i)
		many = append(many, s)
	}
	m.SetSystems(many)
	m.SetMaxPerPage(3)
	got, err := newClient(t, m, beszelmock.Password, nil).Systems(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 || got[6].Name != "host-6" {
		t.Errorf("systems = %+v; want all 7 over 3 pages", got)
	}
}

func TestSystemsErrors(t *testing.T) {
	tests := []struct {
		name     string
		password string
		body     string
		want     string
	}{
		{name: "wrong password", password: "nope", want: "beszel login: HTTP 400: Failed to authenticate. (wrong email or password?)"},
		{name: "malformed", password: beszelmock.Password, body: `{"page":1,"items":[{`, want: "decode response"},
		{name: "wrong shape", password: beszelmock.Password, body: `{"page":1,"items":{"id":"x"}}`, want: "decode response"},
		{name: "html", password: beszelmock.Password, body: `<html>login</html>`, want: "decode response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := beszelmock.New(beszelmock.Email, beszelmock.Password)
			if tt.body != "" {
				m.SetBody(tt.body)
			}
			_, err := newClient(t, m, tt.password, nil).Systems(t.Context())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v; want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), tt.password) {
				t.Errorf("error %q holds the password", err)
			}
		})
	}
}

func TestSystemsTimeout(t *testing.T) {
	m := beszelmock.New(beszelmock.Email, beszelmock.Password)
	release := make(chan struct{})
	defer close(release)
	m.Hang(release)
	c := newClient(t, m, beszelmock.Password, &http.Client{Timeout: 50 * time.Millisecond})
	start := time.Now()
	if _, err := c.Systems(t.Context()); err == nil {
		t.Fatal("no error from a server that never answers")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("took %v; want the client timeout", took)
	}
}

func TestNew(t *testing.T) {
	for _, tt := range []struct{ url, email, password string }{
		{"ftp://x", "e", "p"}, {"http://", "e", "p"}, {"http://u:p@x", "e", "p"}, {"http://x?a=b", "e", "p"},
		{"http://x", "", "p"}, {"http://x", "e", ""},
	} {
		if _, err := beszel.New(tt.url, tt.email, tt.password, nil); err == nil {
			t.Errorf("New(%q, %q) = nil error", tt.url, tt.email)
		}
	}
	c, err := beszel.New("http://beszel.lan:8090/api/", "e", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Target(); got != "beszel:http://beszel.lan:8090" {
		t.Errorf("Target = %q", got)
	}
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// A read goes through policy as beszel.read and is audited; a failed read
// keeps the last systems and says why.
func TestReader(t *testing.T) {
	ctx := t.Context()
	st := newStore(t)
	m := beszelmock.New(beszelmock.Email, beszelmock.Password)
	r := beszel.NewReader(beszel.ReaderConfig{Client: newClient(t, m, beszelmock.Password, nil), Policy: policy.New(st.Audit())})
	if s := r.Snapshot(); s.State != beszel.StateConnecting {
		t.Errorf("state before a read = %q", s.State)
	}
	if err := r.Read(ctx); err != nil {
		t.Fatal(err)
	}
	s := r.Snapshot()
	if s.State != beszel.StateOK || len(s.Systems) != 3 || s.Systems[0].Name != "nas" || s.ReadAt.IsZero() {
		t.Errorf("snapshot = %+v; want 3 systems by name", s)
	}
	m.SetBody(`{`)
	if err := r.Read(ctx); err == nil {
		t.Fatal("no error from a malformed response")
	}
	s = r.Snapshot()
	if s.State != beszel.StateUnavailable || !strings.Contains(s.Error, "decode response") || len(s.Systems) != 3 {
		t.Errorf("snapshot after a failed read = %+v; want the last systems kept", s)
	}
	entries, err := st.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit = %+v; want 2 entries", entries)
	}
	for _, e := range entries {
		if e.Action != string(policy.BeszelRead) || e.ActorKind != policy.ActorHub || !strings.HasPrefix(e.Target, "beszel:http://") {
			t.Errorf("audit entry = %+v", e)
		}
		if strings.Contains(fmt.Sprint(e), beszelmock.Password) {
			t.Errorf("audit entry holds the password: %+v", e)
		}
	}
}

// A policy that denies the read class stops reads before Beszel is asked.
func TestReaderDenied(t *testing.T) {
	ctx := t.Context()
	st := newStore(t)
	cfg := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Read: policy.ModeDeny}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pol := policy.NewWithConfig(st.Audit(), nil, cfg)
	m := beszelmock.New(beszelmock.Email, beszelmock.Password)
	r := beszel.NewReader(beszel.ReaderConfig{Client: newClient(t, m, beszelmock.Password, nil), Policy: pol})
	if err := r.Read(ctx); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("err = %v; want ErrDenied", err)
	}
	if m.Logins() != 0 {
		t.Errorf("logins = %d; want none", m.Logins())
	}
	if s := r.Snapshot(); s.State != beszel.StateUnavailable || len(s.Systems) != 0 {
		t.Errorf("snapshot = %+v", s)
	}
}
