// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	s.authority = func() error { return nil }
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
		vouch  error
	}{
		{"another certificate with the recorded serial", forged, pki.SerialString(genuine), nil},
		{"a certificate without a recorded fingerprint", unrecorded, pki.SerialString(unrecorded), nil},
		{"a hub that cannot vouch for its store", genuine, pki.SerialString(genuine), errors.New("not the leader")},
	}
	for _, tt := range tests {
		s.authority = func() error { return tt.vouch }
		cert, bundle := renew(tt.leaf, tt.serial)
		if cert != nil {
			t.Errorf("%s: renewed", tt.name)
		}
		// An agent adds a CA only with a certificate of it.
		if bundle != nil {
			t.Errorf("%s: the Welcome carries CAs to trust without a certificate", tt.name)
		}
	}

	s.authority = func() error { return nil }
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
	h := requireClientCert(st.Certs(), ca, slog.New(slog.DiscardHandler), func() error { return nil },
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
	if _, err := ca.GenerateNext(time.Now()); err != nil {
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
