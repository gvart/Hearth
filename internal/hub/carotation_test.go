// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// During a hub CA rotation the hub renews an agent only for exactly the
// old-CA certificate recorded for it, and only when it can vouch for its
// store; every Welcome then carries the CAs to trust.
func TestRenewalForCARotation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	oldFP := pki.FingerprintHex(ca.Cert())
	genuine, forged, unrecorded := issueClientCert(t, ca, "pi"), issueClientCert(t, ca, "pi"), issueClientCert(t, ca, "pi")
	if err := st.Certs().Create(ctx, pki.SerialString(unrecorded), "pi"); err != nil {
		t.Fatal(err)
	}
	if err := st.Certs().Record(ctx, store.CertRecord{
		Serial: pki.SerialString(genuine), DeviceID: "pi", Fingerprint: pki.FingerprintHex(genuine), CAFP: oldFP,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewAgentStream(slog.New(slog.DiscardHandler), time.Second, NewRegistry(RegistryConfig{Store: st}))
	s.pins, s.audit, s.ca, s.rotations, s.renew = st.Certs(), st.Audit(), ca, st.CARotations(), st.Certs()
	renew := func(leaf *x509.Certificate, serial string) (cert, bundle []byte) {
		c := context.WithValue(withDeviceID(ctx, "pi"), serialKey{}, serial)
		c = context.WithValue(c, chainKey{}, []*x509.Certificate{leaf})
		return s.renewal(c, s.log, "pi")
	}

	if cert, bundle := renew(genuine, pki.SerialString(genuine)); cert != nil || bundle != nil {
		t.Fatal("renewed or sent CAs with no rotation")
	}
	next, err := ca.GenerateNext(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.TrustNext(next); err != nil { // the rotation under way, as a cluster hub learns
		t.Fatal(err)
	}
	newFP := pki.FingerprintHex(next)
	if err := st.CARotations().Start(ctx, store.CARotation{
		NewCAFP: newFP, OldCAFP: oldFP, NewCACert: string(pki.EncodeCertPEM(next)), Pins: map[string]string{},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		leaf   *x509.Certificate
		serial string
	}{
		{"another certificate with the recorded serial", forged, pki.SerialString(genuine)},
		{"a certificate without a recorded fingerprint", unrecorded, pki.SerialString(unrecorded)},
	}
	for _, tt := range tests {
		cert, bundle := renew(tt.leaf, tt.serial)
		if cert != nil {
			t.Errorf("%s: renewed", tt.name)
		}
		// An agent adds a CA only with a certificate of it.
		if bundle != nil {
			t.Errorf("%s: the Welcome carries CAs to trust without a certificate", tt.name)
		}
	}

	cert, bundle := renew(genuine, pki.SerialString(genuine))
	if cert == nil || strings.Count(string(bundle), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("the recorded certificate was not renewed with both CAs to trust")
	}
	renewed, err := pki.ParseCertPEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	if issuerFP(ca, renewed) != newFP || !renewed.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(genuine.PublicKey) {
		t.Error("the renewed certificate is not of the new CA for the agent's key")
	}
	if id, err := pki.DeviceID(renewed); err != nil || id != "pi" {
		t.Errorf("renewed for %q, %v", id, err)
	}
	if fp, err := st.Certs().Fingerprint(ctx, pki.SerialString(renewed), "pi"); err != nil || fp != "" {
		t.Errorf("renewed certificate recorded with fingerprint %q, %v; want none until the agent presents it", fp, err)
	}
	if cert, _ := renew(renewed, pki.SerialString(renewed)); cert != nil {
		t.Error("a certificate of the new CA was renewed again")
	}
}

// Once a hub CA rotation has finished, a client certificate of the old CA is
// refused, also on a connection opened before the finish.
func TestRequireClientCertRefusesUntrustedCA(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueClientCert(t, ca, "pi")
	if err := st.Certs().Create(t.Context(), pki.SerialString(leaf), "pi"); err != nil {
		t.Fatal(err)
	}
	h := requireClientCert(st.Certs(), ca, slog.New(slog.DiscardHandler),
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	serve := func() int {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, ca.Cert()}}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := serve(); code != http.StatusNoContent {
		t.Fatalf("before the rotation: %d", code)
	}
	if next, err := ca.GenerateNext(time.Now()); err != nil {
		t.Fatal(err)
	} else if err := ca.TrustNext(next); err != nil {
		t.Fatal(err)
	}
	if code := serve(); code != http.StatusNoContent {
		t.Fatalf("in the window: %d", code)
	}
	if err := ca.Finish(); err != nil {
		t.Fatal(err)
	}
	if code := serve(); code == http.StatusNoContent {
		t.Fatal("an old-CA client certificate is accepted after the finish")
	}
	// A stream opened before the finish ends on its next heartbeat.
	s := NewAgentStream(slog.New(slog.DiscardHandler), time.Second, NewRegistry(RegistryConfig{Store: st}))
	s.ca, s.certs = ca, st.Certs()
	c := context.WithValue(withDeviceID(t.Context(), "pi"), serialKey{}, pki.SerialString(leaf))
	c = context.WithValue(c, chainKey{}, []*x509.Certificate{leaf})
	if err := s.recheckCert(c, s.log, "pi"); !errors.Is(err, errUntrustedCA) {
		t.Errorf("recheckCert of an old-CA stream after the finish = %v, want errUntrustedCA", err)
	}
}

// lateRotation is the store's CA rotations, except that the first read finds
// none: a hub CA rotation that starts while an agent connects, after the
// hub's first look at it.
type lateRotation struct {
	rotationReader
	reads atomic.Int32
}

func (r *lateRotation) Latest(ctx context.Context) (store.CARotation, error) {
	if r.reads.Add(1) == 1 {
		return store.CARotation{}, store.ErrNotFound
	}
	return r.rotationReader.Latest(ctx)
}

// A hub CA rotation that starts while an agent connects reaches the agent:
// the stream whose Welcome did not renew it ends on its next heartbeat, so
// that it reconnects for its certificate and CAs.
func TestRotationStartedWhileConnecting(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	f := newRevokeFixture(t)
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next, err := ca.GenerateNext(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.CARotations().Start(ctx, store.CARotation{
		NewCAFP: pki.FingerprintHex(next), OldCAFP: pki.FingerprintHex(ca.Cert()),
		NewCACert: string(pki.EncodeCertPEM(next)), Pins: map[string]string{},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.as.ca, f.as.rotations = ca, &lateRotation{rotationReader: f.st.CARotations()}
	f.chains = map[string][]*x509.Certificate{"dev-1": {issueClientCert(t, ca, "dev-1"), ca.Cert()}}

	stream := f.open(ctx, t, "dev-1", "0a")
	if err := stream.Send(heartbeat()); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if err := stream.CloseRequest(); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Receive()
	if connect.CodeOf(err) != connect.CodeUnavailable || !strings.Contains(err.Error(), "rotation moved") {
		t.Fatalf("the stream after a heartbeat ended with %v, want the rotation moved on", err)
	}
}
