// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
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
	connected := func(n int) func() bool {
		return func() bool { return strings.Count(h.logs.String(), `msg="agent connected" device_id=`+id) >= n }
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
	newFP := pki.FingerprintHex(next)
	if err := h.st.CARotations().Start(ctx, store.CARotation{
		NewCAFP: newFP, OldCAFP: oldFP, NewCACert: string(pki.EncodeCertPEM(next)), Pins: map[string]string{},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	h.stop()
	h.start()

	// One connection renews, the next uses the renewed certificate.
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
	h.stop()
	h.start()
	waitFor(t, 10*time.Second, "the agent to reconnect and drop the old CA", func() bool {
		b, err := os.ReadFile(filepath.Join(dataDir, agent.CAFile))
		return err == nil && strings.Count(string(b), "BEGIN CERTIFICATE") == 1 && connected(5)()
	})
	a.assertRunning(t)

	// The old certificate is refused once the old CA is gone.
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert())
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{oldPair},
	}}}
	defer c.CloseIdleConnections()
	resp, err := c.Get(h.url + "/api/v1/devices")
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("the old agent certificate got %s after the finish", resp.Status)
		}
	}
}
