// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// A named token names the device it enrolls; an unnamed one leaves it its
// hostname. A named token is single use and expires like any other, and the
// name stays when the agent later reports another hostname.
func TestEnrollNamedToken(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e := NewEnroller(st, ca, policy.New(st.Audit()), slog.New(slog.DiscardHandler))
	newToken := func(name string, expires time.Time) string {
		t.Helper()
		tok, err := pki.NewToken(ca.Cert())
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Tokens().CreateNamed(t.Context(), tok.Secret, name, nil, expires); err != nil {
			t.Fatal(err)
		}
		return tok.Secret
	}
	enroll := func(secret string) (*connect.Response[agentv1.EnrollResponse], error) {
		t.Helper()
		key, err := pki.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		csr, err := pki.NewCSR(key, "raspberrypi")
		if err != nil {
			t.Fatal(err)
		}
		return e.Enroll(t.Context(), connect.NewRequest(&agentv1.EnrollRequest{TokenSecret: secret, Csr: csr, Hostname: "raspberrypi"}))
	}
	deviceOf := func(resp *connect.Response[agentv1.EnrollResponse]) store.Device {
		t.Helper()
		d, err := st.Devices().Get(t.Context(), resp.Msg.GetDeviceId())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	named := newToken("garage-pi", time.Now().Add(time.Minute))
	resp, err := enroll(named)
	if err != nil {
		t.Fatal(err)
	}
	if d := deviceOf(resp); d.Name != "garage-pi" || d.Hostname != "raspberrypi" {
		t.Errorf("named enrollment: name %q hostname %q, want garage-pi and raspberrypi", d.Name, d.Hostname)
	}
	if _, _, err := st.Devices().ReportFacts(t.Context(), resp.Msg.GetDeviceId(), store.DeviceFacts{Hostname: "renamed-host"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if d := deviceOf(resp); d.Name != "garage-pi" {
		t.Errorf("name after a new hostname = %q, want garage-pi", d.Name)
	}

	resp, err = enroll(newToken("", time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if d := deviceOf(resp); d.Name != "raspberrypi" {
		t.Errorf("unnamed enrollment: name %q, want the hostname raspberrypi", d.Name)
	}

	// Refused: a named token spent already, or expired.
	expired := newToken("attic-pi", time.Now().Add(-time.Second))
	for what, secret := range map[string]string{"reused": named, "expired": expired} {
		if _, err := enroll(secret); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s named token: err = %v, want unauthenticated", what, err)
		}
	}
	devices, err := st.Devices().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Errorf("%d devices, want 2: refused enrollments must not add one", len(devices))
	}
}
