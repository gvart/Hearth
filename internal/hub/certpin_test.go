// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Enrollment records the issued certificate's fingerprint and its CA's.
func TestEnrollRecordsFingerprint(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := pki.NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Tokens().Create(t.Context(), tok.Secret, nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "pi")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEnroller(st, ca, policy.New(st.Audit()), slog.New(slog.DiscardHandler))
	resp, err := e.Enroll(t.Context(), connect.NewRequest(&agentv1.EnrollRequest{TokenSecret: tok.Secret, Csr: csr, Hostname: "pi"}))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(resp.Msg.GetCertificate())
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Certs().Fingerprint(t.Context(), pki.SerialString(cert), resp.Msg.GetDeviceId())
	if err != nil || got != pki.FingerprintHex(cert) {
		t.Errorf("recorded fingerprint = %q, %v; want %q", got, err, pki.FingerprintHex(cert))
	}
}

// A certificate recorded without a fingerprint is pinned to the first one
// presented with it; a later, different certificate with the same serial and
// device ID is reported and leaves the pin alone. A hub that cannot vouch for
// its store pins nothing.
func TestPinCertOnConnect(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	issue := func() *x509.Certificate {
		t.Helper()
		key, err := pki.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		csr, err := pki.NewCSR(key, "pi")
		if err != nil {
			t.Fatal(err)
		}
		c, err := ca.SignClientCSR(csr, "pi", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	genuine, forged := issue(), issue()
	serial := pki.SerialString(genuine)
	if err := st.Certs().Create(t.Context(), serial, "pi"); err != nil {
		t.Fatal(err)
	}

	var logs syncBuffer
	s := NewAgentStream(slog.New(slog.NewTextHandler(&logs, nil)), time.Second, NewRegistry(RegistryConfig{Store: st}))
	s.pins = st.Certs()
	connectAs := func(leaf *x509.Certificate) {
		ctx := context.WithValue(withDeviceID(t.Context(), "pi"), serialKey{}, serial)
		ctx = context.WithValue(ctx, leafKey{}, leaf)
		s.pinCert(ctx, s.log, "pi")
	}
	recorded := func() string {
		fp, err := st.Certs().Fingerprint(t.Context(), serial, "pi")
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}

	s.authority = func() error { return errors.New("not the leader") }
	connectAs(genuine)
	if fp := recorded(); fp != "" {
		t.Fatalf("a hub that cannot vouch pinned %q", fp)
	}

	s.authority = func() error { return nil }
	connectAs(genuine)
	if fp := recorded(); fp != pki.FingerprintHex(genuine) {
		t.Fatalf("pinned %q, want the presented certificate's %q", fp, pki.FingerprintHex(genuine))
	}
	connectAs(forged)
	if fp := recorded(); fp != pki.FingerprintHex(genuine) {
		t.Errorf("a second certificate replaced the pin: %q", fp)
	}
	if !strings.Contains(logs.String(), "not the one recorded for its serial") {
		t.Errorf("the mismatch was not logged: %s", logs.String())
	}
}
