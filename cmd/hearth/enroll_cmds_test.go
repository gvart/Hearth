// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd(buildInfo{Version: "dev"})
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return out.String(), err
}

// initHub creates a hub data dir as `hearth hub` would on first start.
func initHub(t *testing.T) (string, *pki.CA) {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	storetest.Migrated(t, filepath.Join(dir, dbFile))
	return dir, ca
}

func openStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(dir, dbFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestTokenCreate(t *testing.T) {
	dir, ca := initHub(t)
	out, err := execute(t, "token", "create", "--data-dir", dir, "--ttl", "5m",
		"--labels", "room=attic", "--hub-url", "https://hub.lan:7443")
	if err != nil {
		t.Fatalf("token create: %v\n%s", err, out)
	}

	var raw string
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "hearth2.") {
			raw = f
			break
		}
	}
	tok, err := pki.ParseToken(raw)
	if err != nil {
		t.Fatalf("output has no valid token: %v\n%s", err, out)
	}
	if tok.CAFingerprint != ca.Fingerprint() {
		t.Error("token is not pinned to the hub CA")
	}
	if tok.HubURL != "https://hub.lan:7443" {
		t.Errorf("token names hub %q, want https://hub.lan:7443", tok.HubURL)
	}
	if want := "HEARTH_TOKEN=" + raw + " hearth agent join https://hub.lan:7443\n"; !strings.Contains(out, want) {
		t.Errorf("output lacks join one-liner %q:\n%s", want, out)
	}

	st := openStore(t, dir)
	got, err := st.Tokens().Consume(t.Context(), tok.Secret, time.Now())
	if err != nil || got.Labels["room"] != "attic" {
		t.Errorf("Consume = %+v, %v; want the created token with labels", got, err)
	}
	if _, err := st.Tokens().Consume(t.Context(), tok.Secret, time.Now().Add(6*time.Minute)); !errors.Is(err, store.ErrTokenUsed) {
		t.Errorf("second Consume err = %v, want ErrTokenUsed", err)
	}
	entries, err := st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != string(policy.TokenCreate) || entries[0].ActorKind != policy.ActorAdmin {
		t.Fatalf("audit = %+v, want one token.create by admin", entries)
	}
	if strings.Contains(string(entries[0].Detail), tok.Secret) {
		t.Error("audit detail contains the token secret")
	}
}

// --name is stored with the token: the device that enrolls takes it.
func TestTokenCreateNamed(t *testing.T) {
	dir, _ := initHub(t)
	out, err := execute(t, "token", "create", "--data-dir", dir, "--name", "garage-pi")
	if err != nil {
		t.Fatalf("token create: %v\n%s", err, out)
	}
	var raw string
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "hearth2.") {
			raw = f
			break
		}
	}
	tok, err := pki.ParseToken(raw)
	if err != nil {
		t.Fatalf("output has no valid token: %v\n%s", err, out)
	}
	got, err := openStore(t, dir).Tokens().Consume(t.Context(), tok.Secret, time.Now())
	if err != nil || got.Name != "garage-pi" {
		t.Errorf("Consume = %+v, %v; want the name garage-pi", got, err)
	}
}

func TestTokenCreateRejects(t *testing.T) {
	dir, _ := initHub(t)
	tests := []struct {
		name string
		args []string
	}{
		{"zero ttl", []string{"token", "create", "--data-dir", dir, "--ttl", "0s"}},
		{"no hub in data dir", []string{"token", "create", "--data-dir", t.TempDir()}},
		{"name too long", []string{"token", "create", "--data-dir", dir, "--name", strings.Repeat("a", 64)}},
		{"name with a space", []string{"token", "create", "--data-dir", dir, "--name", "garage pi"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if out, err := execute(t, tt.args...); err == nil {
				t.Fatalf("want error, got output:\n%s", out)
			}
		})
	}
}

func TestDeviceRevoke(t *testing.T) {
	dir, _ := initHub(t)
	st := openStore(t, dir)
	now := time.Now()
	if err := st.Devices().Upsert(t.Context(), store.Device{ID: "pi", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.Certs().Create(t.Context(), "0a", "pi"); err != nil {
		t.Fatal(err)
	}

	out, err := execute(t, "device", "revoke", "pi", "--data-dir", dir)
	if err != nil {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Revoked 1 certificate(s) of device pi") {
		t.Errorf("output = %q", out)
	}
	if err := st.Certs().Check(t.Context(), "0a", "pi"); !errors.Is(err, store.ErrCertRevoked) {
		t.Errorf("Check after revoke = %v, want ErrCertRevoked", err)
	}

	if _, err := execute(t, "device", "revoke", "ghost", "--data-dir", dir); err == nil {
		t.Error("revoke unknown device: want error")
	}
	if _, err := execute(t, "device", "revoke", "pi", "--data-dir", t.TempDir()); err == nil {
		t.Error("revoke with no hub database: want error")
	}

	entries, err := st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit entries = %d, want 2 (revoke pi, revoke ghost)", len(entries))
	}
	for _, e := range entries {
		if e.Action != string(policy.DeviceRevoke) || e.Decision != policy.Allow {
			t.Errorf("audit entry = %+v, want allowed device.revoke", e)
		}
	}
	if entries[0].Target != "ghost" || !strings.HasPrefix(entries[0].Result, "error:") {
		t.Errorf("failed revoke audited as %+v", entries[0])
	}
}

func TestAgentJoinRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"malformed token", []string{"agent", "join", "https://hub.lan:7443", "nope", "--data-dir", t.TempDir()}},
		{"plain http hub", []string{
			"agent", "join", "http://hub.lan:7443",
			"hearth1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"--data-dir", t.TempDir(),
		}},
		{"missing token", []string{"agent", "join", "https://hub.lan:7443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := execute(t, tt.args...); err == nil {
				t.Fatal("want error")
			}
		})
	}
}
