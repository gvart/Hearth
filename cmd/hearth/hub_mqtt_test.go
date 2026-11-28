// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

func TestNewMQTTBroker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(dir, dbFile))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := newLogger(io.Discard)
	serverCert := func() *tls.Certificate { return &cert }

	// Off by default.
	if b, err := newMQTTBroker(ctx, hubOptions{dataDir: dir}, ca, serverCert, st, nil, log); b != nil || err != nil {
		t.Fatalf("without --mqtt-listen: %v, %v", b, err)
	}
	bridgeOnly := hubOptions{dataDir: dir, mqtt: mqttOptions{bridge: filepath.Join(dir, "bridge.yaml")}}
	if _, err := newMQTTBroker(ctx, bridgeOnly, ca, serverCert, st, nil, log); err == nil || !strings.Contains(err.Error(), "needs --mqtt-listen") {
		t.Fatalf("--mqtt-bridge without --mqtt-listen: %v", err)
	}
	on := hubOptions{dataDir: dir, mqtt: mqttOptions{listen: "127.0.0.1:0"}}
	if _, err := newMQTTBroker(ctx, on, ca, serverCert, st, nil, log); err == nil || !strings.Contains(err.Error(), "mqtt.yaml") {
		t.Fatalf("without a clients file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mqtt.yaml"), []byte("users:\n  - name: u\n    password_hash: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newMQTTBroker(ctx, on, ca, serverCert, st, nil, log); err == nil {
		t.Fatal("accepted a clients file with a plain password")
	}
	if err := os.WriteFile(filepath.Join(dir, "mqtt.yaml"), []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bridged := on
	bridged.mqtt.bridge = filepath.Join(dir, "missing-bridge.yaml")
	if _, err := newMQTTBroker(ctx, bridged, ca, serverCert, st, nil, log); err == nil || !strings.Contains(err.Error(), "--mqtt-bridge") {
		t.Fatalf("missing bridge file: %v", err)
	}
	b, err := newMQTTBroker(ctx, on, ca, serverCert, st, nil, log)
	if err != nil || b == nil {
		t.Fatalf("newMQTTBroker: %v", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- b.Run(runCtx) }()
	conn, err := tls.Dial("tcp", b.Addr().String(), &tls.Config{RootCAs: ca.Pool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("TLS to the broker: %v", err)
	}
	_ = conn.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestMQTTHashPassword(t *testing.T) {
	cmd := newMQTTCmd()
	var out bytes.Buffer
	cmd.SetIn(strings.NewReader("s3cret\n"))
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"hash-password"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if h := strings.TrimSpace(out.String()); !strings.HasPrefix(h, "$2a$") || strings.Contains(h, "s3cret") {
		t.Fatalf("hash %q", h)
	}
	cmd.SetIn(strings.NewReader("\n"))
	if err := cmd.Execute(); err == nil {
		t.Fatal("hashed an empty password")
	}
}
