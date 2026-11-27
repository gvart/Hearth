// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func executeWithStdin(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd(buildInfo{Version: "dev"})
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return out.String(), err
}

// TestAdminSetPasswordNeedsMaster: on a storage-only cluster member, which
// holds no CA key and writes no global rows (#382), set-password refuses.
func TestAdminSetPasswordNeedsMaster(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, cluster.StateDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, dbFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeWithStdin(t, "s3cret-admin-pw\n", "admin", "set-password", "--data-dir", dir)
	if err == nil || !strings.Contains(err.Error(), "not a master") {
		t.Fatalf("set-password on a storage member = %v", err)
	}
}

func TestAdminSetPassword(t *testing.T) {
	const pw = "s3cret-admin-pw"
	dir, _ := initHub(t)

	tests := []struct {
		name    string
		dataDir string
		stdin   string
		wantErr string
	}{
		{"too short", dir, "short\n", "at least"},
		{"empty", dir, "", "at least"},
		{"wrong data dir", t.TempDir(), pw + "\n", "has `hearth hub` been started"},
		{"ok", dir, pw + "\n", ""},
		{"reset", dir, "another-password\r\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := executeWithStdin(t, tt.stdin, "admin", "set-password", "--data-dir", tt.dataDir)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("set-password: %v\n%s", err, out)
			}
			if strings.Contains(out, strings.TrimSpace(tt.stdin)) {
				t.Errorf("output echoes the password: %s", out)
			}
		})
	}

	st := openStore(t, dir)
	if _, err := st.Admin().PasswordHash(t.Context()); err != nil {
		t.Fatalf("no password stored: %v", err)
	}
	entries, err := st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var sets int
	for _, e := range entries {
		if e.Action == string(policy.AdminSetPassword) && e.ActorKind == policy.ActorAdmin && e.Decision == policy.Allow {
			sets++
		}
	}
	if sets != 2 {
		t.Errorf("admin.set_password audit entries = %d, want 2", sets)
	}
}

func TestEnsureAdminPassword(t *testing.T) {
	const pw = "from-the-environment"
	tests := []struct {
		name      string
		preset    bool
		env       string
		wantLog   string
		wantSet   bool
		wantError bool
	}{
		{"no password, no env: hint", false, "", "hearth admin set-password --data-dir", false, false},
		{"env sets password", false, pw, "admin password set from HEARTH_ADMIN_PASSWORD", true, false},
		{"env ignored when already set", true, pw, "ignoring HEARTH_ADMIN_PASSWORD", true, false},
		{"env too short", false, "short", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, _ := initHub(t)
			st := openStore(t, dir)
			pol := policy.New(st.Audit())
			if tt.preset {
				if err := st.Admin().SetPasswordHash(t.Context(), "preset-hash"); err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			err := ensureAdminPassword(t.Context(), st, pol, hubOptions{dataDir: dir, adminPassword: tt.env},
				slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			if (err != nil) != tt.wantError {
				t.Fatalf("err = %v, wantError %v", err, tt.wantError)
			}
			if tt.env != "" && (strings.Contains(logs.String(), tt.env) || (err != nil && strings.Contains(err.Error(), tt.env))) {
				t.Fatalf("password leaked into logs or error:\n%s", logs.String())
			}
			if !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("logs lack %q:\n%s", tt.wantLog, logs.String())
			}
			h, err := st.Admin().PasswordHash(t.Context())
			if gotSet := err == nil; gotSet != tt.wantSet {
				t.Errorf("password set = %v, want %v (%v)", gotSet, tt.wantSet, err)
			}
			if tt.preset && h != "preset-hash" {
				t.Error("env overwrote an existing password")
			}
			if !tt.wantSet && !errors.Is(err, store.ErrNotFound) {
				t.Errorf("PasswordHash err = %v, want ErrNotFound", err)
			}
		})
	}
}

// lockedBuffer collects the hub's logs while it runs.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunHubServesAPIAndStops(t *testing.T) {
	dir := t.TempDir()
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runHub(ctx, hubOptions{
			dataDir: dir, listen: "127.0.0.1:0", httpListen: "127.0.0.1:0", hosts: []string{"127.0.0.1"},
			cluster: clusterOptions{listen: "127.0.0.1:0"},
		}, slog.New(slog.NewTextHandler(logs, nil)))
	}()

	addrRe := regexp.MustCompile(`http_addr=(\S+)`)
	var httpAddr string
	for deadline := time.Now().Add(10 * time.Second); httpAddr == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if m := addrRe.FindStringSubmatch(logs.String()); m != nil {
			httpAddr = m[1]
		}
	}
	if httpAddr == "" {
		t.Fatalf("hub did not start:\n%s", logs.String())
	}
	// The hint comes once the member has caught up, after the listeners.
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(logs.String(), "admin password not set") && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "admin password not set") {
		t.Errorf("no set-password hint in logs:\n%s", logs.String())
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+httpAddr+"/api/v1/devices", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/devices = %d, want 401", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runHub = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hub did not stop on cancel")
	}
}
