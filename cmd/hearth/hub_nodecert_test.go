// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

// TestClusterHubServesNodeCert: a clustered hub's listener answers a hub
// asking for its node certificate (the server name internal/cluster's
// pinning client sends during a hub CA rotation) with it, and every other
// client with its server certificate.
func TestClusterHubServesNodeCert(t *testing.T) {
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runHub(ctx, hubOptions{
			dataDir: t.TempDir(), listen: "127.0.0.1:0", httpListen: "127.0.0.1:0", hosts: []string{"127.0.0.1"},
			cluster: clusterOptions{form: true, nodeID: "h1", raftListen: "127.0.0.1:0"},
		}, slog.New(slog.NewTextHandler(logs, nil)))
	}()
	addrRe := regexp.MustCompile(`msg="hub listening".* addr=(\S+)`)
	var addr string
	for deadline := time.Now().Add(15 * time.Second); addr == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if m := addrRe.FindStringSubmatch(logs.String()); m != nil {
			addr = m[1]
		}
	}
	if addr == "" {
		t.Fatalf("hub did not start:\n%s", logs.String())
	}

	for _, tc := range []struct {
		sni      string
		wantNode bool
	}{
		{"node.hearth-hub.invalid", true},
		{"127.0.0.1", false},
	} {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{
			MinVersion: tls.VersionTLS13, ServerName: tc.sni,
			InsecureSkipVerify: true, //nolint:gosec // only the certificate presented is looked at
		}}
		c, err := d.DialContext(t.Context(), "tcp", addr)
		if err != nil {
			t.Fatalf("SNI %q: %v", tc.sni, err)
		}
		leaf := c.(*tls.Conn).ConnectionState().PeerCertificates[0]
		_ = c.Close()
		id, err := pki.HubNodeID(leaf)
		if got := err == nil && id == "h1"; got != tc.wantNode {
			t.Errorf("SNI %q: node certificate of h1 = %v (%q, %v), want %v", tc.sni, got, id, err, tc.wantNode)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runHub = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("hub did not stop on cancel")
	}
}
