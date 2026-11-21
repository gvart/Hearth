// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/x509"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
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

func issueClientCert(t *testing.T, ca *pki.CA, id string) *x509.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, id)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.SignClientCSR(csr, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A certificate recorded without a fingerprint is pinned, with its CA's, to
// the first one presented with it; a later, different certificate with the
// same serial and device ID leaves the pin alone and is recorded as a
// mismatch, once, on the certificate and in the audit log. A hub that cannot
// vouch for its store pins nothing.
func TestPinCertOnConnect(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	genuine, forged := issueClientCert(t, ca, "pi"), issueClientCert(t, ca, "pi")
	serial := pki.SerialString(genuine)
	if err := st.Certs().Create(t.Context(), serial, "pi"); err != nil {
		t.Fatal(err)
	}

	var logs syncBuffer
	s := NewAgentStream(slog.New(slog.NewTextHandler(&logs, nil)), time.Second, NewRegistry(RegistryConfig{Store: st}))
	s.pins, s.audit = st.Certs(), st.Audit()
	connectAs := func(leaf *x509.Certificate) bool {
		ctx := context.WithValue(withDeviceID(t.Context(), "pi"), serialKey{}, serial)
		ctx = context.WithValue(ctx, chainKey{}, []*x509.Certificate{leaf, ca.Cert()})
		return s.pinCert(ctx, s.log, "pi")
	}
	recorded := func() string {
		fp, err := st.Certs().Fingerprint(t.Context(), serial, "pi")
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
	mismatches := func() int {
		entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{ActionCertMismatch}}, 10)
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}

	if !connectAs(genuine) {
		t.Error("pinning reported the certificate unsettled")
	}
	if fp := recorded(); fp != pki.FingerprintHex(genuine) {
		t.Fatalf("pinned %q, want the presented certificate's %q", fp, pki.FingerprintHex(genuine))
	}
	for range 2 {
		if !connectAs(forged) {
			t.Error("a recorded mismatch reported the certificate unsettled")
		}
	}
	if fp := recorded(); fp != pki.FingerprintHex(genuine) {
		t.Errorf("a second certificate replaced the pin: %q", fp)
	}
	if got, err := st.Certs().PinMismatches(t.Context(), "pi"); err != nil || len(got) != 1 {
		t.Errorf("PinMismatches = %v, %v; want the serial", got, err)
	}
	if n := mismatches(); n != 1 {
		t.Errorf("%d %s audit entries, want 1", n, ActionCertMismatch)
	}
	if !strings.Contains(logs.String(), "not the one recorded for its serial") {
		t.Errorf("the mismatch was not logged: %s", logs.String())
	}
}

// oldSchemaPins is store.Certs on a store whose schema records no
// fingerprints yet, until migrated is set.
type oldSchemaPins struct {
	certPinner
	migrated *atomic.Bool
}

func (p oldSchemaPins) Fingerprint(ctx context.Context, serial, deviceID string) (string, error) {
	if !p.migrated.Load() {
		return "", store.ErrSchemaTooOld
	}
	return p.certPinner.Fingerprint(ctx, serial, deviceID)
}

// A stream that was open while the hub could not pin, as when the cluster
// migrated to the schema that records fingerprints under it, is pinned on a
// later heartbeat rather than on the agent's next connect.
func TestPinCertOnHeartbeat(t *testing.T) {
	t.Parallel()
	var migrated atomic.Bool
	f := newRevokeFixture(t)
	f.as.pins, f.as.audit = oldSchemaPins{certPinner: f.st.Certs(), migrated: &migrated}, f.st.Audit()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueClientCert(t, ca, "dev-1")
	f.chains = map[string][]*x509.Certificate{"dev-1": {leaf, ca.Cert()}}
	stream := f.open(t.Context(), t, "dev-1", "0a")
	if fp, err := f.st.Certs().Fingerprint(t.Context(), "0a", "dev-1"); err != nil || fp != "" {
		t.Fatalf("pinned at connect on the old schema: %q, %v", fp, err)
	}
	migrated.Store(true)
	if err := stream.Send(heartbeat()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate pinned on a heartbeat", func() bool {
		fp, err := f.st.Certs().Fingerprint(t.Context(), "0a", "dev-1")
		return err == nil && fp == pki.FingerprintHex(leaf)
	})
}
