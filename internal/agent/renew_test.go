// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// TestRunRenewsForCARotation follows an agent through a hub CA rotation: on
// its next connection the hub hands it a certificate of the new CA and both
// CAs to trust, the agent reconnects with them at once, and after the finish
// it still connects while its old certificate is refused.
func TestRunRenewsForCARotation(t *testing.T) {
	ctx := t.Context()
	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	a := startAgent(t, dataDir)
	// Counted on the agent, which logs a connection once it has the Welcome:
	// the hub logs it before it reads the rotation for the Welcome, so a
	// rotation step made then would already be in that Welcome and leave a
	// connection out of the count.
	connected := func(n int) func() bool {
		return func() bool { return strings.Count(a.logs.String(), `msg="connected to hub"`) >= n }
	}
	waitFor(t, 10*time.Second, "first connection", connected(1))
	oldPair, err := tls.LoadX509KeyPair(filepath.Join(dataDir, agent.CertFile), filepath.Join(dataDir, agent.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	oldFP := pki.FingerprintHex(h.ca.Cert())

	next, err := h.ca.GenerateNext(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.ca.TrustNext(next); err != nil { // the rotation under way, as a cluster hub learns
		t.Fatal(err)
	}
	newFP := pki.FingerprintHex(next)
	if err := h.st.CARotations().Start(ctx, store.CARotation{
		NewCAFP: newFP, OldCAFP: oldFP, NewCACert: string(pki.EncodeCertPEM(next)), Pins: map[string]string{},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// No hub restart: the open stream ends on its next heartbeat, the next
	// connection renews, and the one after uses the renewed certificate.
	waitFor(t, 10*time.Second, "the agent to reconnect with its renewed certificate", connected(3))
	pair, err := tls.LoadX509KeyPair(filepath.Join(dataDir, agent.CertFile), filepath.Join(dataDir, agent.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if issuer := h.ca.IssuerOf(leaf); issuer == nil || pki.FingerprintHex(issuer) != newFP {
		t.Fatal("the agent certificate is not of the new CA")
	}
	caPEM, err := os.ReadFile(filepath.Join(dataDir, agent.CAFile))
	if err != nil || strings.Count(string(caPEM), "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("the agent trusts %q, %v; want both CAs", caPEM, err)
	}
	waitFor(t, 5*time.Second, "the renewed certificate to be pinned", func() bool {
		fp, err := h.st.Certs().Fingerprint(ctx, pki.SerialString(leaf), id)
		return err == nil && fp == pki.FingerprintHex(leaf)
	})
	if old, err := h.st.CARotations().OldCADevices(ctx, newFP); err != nil || len(old) != 0 {
		t.Fatalf("devices still on the old CA = %v, %v; want none", old, err)
	}

	for _, step := range []struct{ from, to string }{
		{store.CAStageStarted, store.CAStageCutover}, {store.CAStageCutover, store.CAStageFinished},
	} {
		if err := h.st.CARotations().Advance(ctx, newFP, step.from, step.to, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.ca.Cutover(); err != nil {
		t.Fatal(err)
	}
	if err := h.ca.Finish(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the agent to reconnect and drop the old CA", func() bool {
		b, err := os.ReadFile(filepath.Join(dataDir, agent.CAFile))
		return err == nil && strings.Count(string(b), "BEGIN CERTIFICATE") == 1 && connected(5)()
	})
	a.assertRunning(t)

	// The old certificate is refused once the old CA is gone: the hub ends
	// the handshake.
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert())
	c, err := tls.Dial("tcp", h.addr, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{oldPair}})
	if err == nil {
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(make([]byte, 1))
	}
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("the old agent certificate after the finish: %v, want a handshake refusal", err)
	}
}
