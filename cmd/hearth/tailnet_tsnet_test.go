// SPDX-License-Identifier: AGPL-3.0-only

//go:build tailscale

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/gvart/hearth/internal/hub"
)

// startControl runs a Tailscale coordination server and DERP relay on
// loopback that admit only nodes with testKey, and points the hub's node at
// it: tsnet reads TS_CONTROL_URL.
func startControl(t *testing.T) string {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	control := &testcontrol.Server{
		DERPMap:        integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"),
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
		RequireAuthKey: testKey,
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	t.Setenv("TS_CONTROL_URL", control.HTTPTestServer.URL)
	return control.HTTPTestServer.URL
}

// TestTsnetHub runs the hub's tailnet node against a test tailnet, and a
// second node, a phone, that reaches the hub there: agents' TLS with the hub
// CA by the MagicDNS name, and plain HTTP for install.sh.
func TestTsnetHub(t *testing.T) {
	controlURL := startControl(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	log := slog.New(slog.DiscardHandler)

	dir := filepath.Join(t.TempDir(), tailscaleDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := tailnetConfig{hostname: "hearth", dir: dir, authKey: testKey}
	node, err := newTailnetNode(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	tn := newTailnet(cfg, log)
	s := testServe(t)
	done := make(chan error, 1)
	go func() { done <- tn.run(ctx, node, s) }()
	st := waitTailnetFor(t, tn, hub.TailnetRunning, time.Minute)
	if !strings.HasPrefix(st.DNSName, "hearth.") || len(st.IPs) == 0 {
		t.Fatalf("status %+v", st)
	}
	// The test tailnet advertises certificate domains, so 443 listens; the
	// fallback to 7443 is TestTailnetServes'.
	if st.URL != "https://"+st.DNSName+"/" || st.AgentURL != "https://"+st.DNSName+":7443" {
		t.Errorf("url %q agent url %q", st.URL, st.AgentURL)
	}

	phone := &tsnet.Server{
		Dir: t.TempDir(), ControlURL: controlURL, Hostname: "phone", Store: new(mem.Store), Ephemeral: true,
		AuthKey: testKey, Logf: logger.Discard, UserLogf: logger.Discard,
	}
	t.Cleanup(func() { _ = phone.Close() })
	if _, err := phone.Up(ctx); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.ca.Cert())
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return phone.Dial(ctx, network, addr)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: st.DNSName},
	}}
	get := func(url string) string {
		t.Helper()
		var last error
		for range 30 {
			res, err := client.Get(url)
			if err == nil {
				body, _ := io.ReadAll(res.Body)
				_ = res.Body.Close()
				return string(body)
			}
			last = err
			time.Sleep(time.Second)
		}
		t.Fatalf("GET %s: %v", url, last)
		return ""
	}
	ip := st.IPs[0]
	if body := get("https://" + net.JoinHostPort(ip, "7443") + "/"); body != "agent" {
		t.Errorf("agent port body %q", body)
	}
	if body := get("http://" + net.JoinHostPort(ip, "7080") + "/"); body != "web" {
		t.Errorf("http port body %q", body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("run: %v", err)
	}
	_ = node.Close()
	// The node is logged in now: a restart needs no auth key.
	if _, err := os.Stat(filepath.Join(dir, tailscaleStateFile)); err != nil {
		t.Errorf("no node state after login: %v", err)
	}
}

// TestTsnetBadKey checks that a key the tailnet refuses leaves the hub
// running, with the reason in its status and without the key.
func TestTsnetBadKey(t *testing.T) {
	startControl(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	log := slog.New(slog.DiscardHandler)
	const bad = "tskey-auth-kBAD-SecretPartWrong"
	cfg := tailnetConfig{hostname: "hearth", dir: t.TempDir(), authKey: bad}
	node, err := newTailnetNode(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = node.Close() }()
	tn := newTailnet(cfg, log)
	if err := tn.run(ctx, node, testServe(t)); err != nil {
		t.Fatalf("run = %v, want nil", err)
	}
	st := tn.Status()
	if st.State != hub.TailnetError || st.Error == "" || strings.Contains(st.Error, "SecretPart") {
		t.Errorf("status %+v", st)
	}
}

func waitTailnetFor(t *testing.T, tn *tailnet, state string, d time.Duration) hub.TailnetStatus {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		st := tn.Status()
		if st.State == state {
			return st
		}
		if st.State == hub.TailnetError {
			t.Fatalf("tailnet error: %s", st.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tailnet state %q, want %q", tn.Status().State, state)
	return hub.TailnetStatus{}
}
