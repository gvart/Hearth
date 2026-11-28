// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
)

const testKey = "tskey-auth-kTEST123CNTRL-SecretPart456"

func TestTailscaleResolve(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "ts.key")
	if err := os.WriteFile(keyFile, []byte(testKey+"-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openFile := filepath.Join(t.TempDir(), "open.key")
	if err := os.WriteFile(openFile, []byte(testKey), 0o644); err != nil { //nolint:gosec // exposed on purpose
		t.Fatal(err)
	}
	loggedIn := t.TempDir()
	if err := os.MkdirAll(filepath.Join(loggedIn, tailscaleDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loggedIn, tailscaleDir, tailscaleStateFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	on := func(o tailscaleOptions) tailscaleOptions {
		o.enabled = true
		if o.hostname == "" {
			o.hostname = defaultTailscaleHostname
		}
		return o
	}
	tests := []struct {
		name    string
		opts    tailscaleOptions
		dataDir string
		built   bool
		wantKey string
		wantErr string
		wantNil bool
	}{
		{name: "off", opts: tailscaleOptions{authKey: testKey}, built: true, wantNil: true},
		{name: "key file without --tailscale", opts: tailscaleOptions{authKeyFile: keyFile}, built: true, wantErr: "needs --tailscale"},
		{name: "build without tailscale", opts: on(tailscaleOptions{authKey: testKey}), built: false, wantErr: "this build has no Tailscale"},
		{name: "env key", opts: on(tailscaleOptions{authKey: testKey}), built: true, wantKey: testKey},
		{name: "file flag wins over env", opts: on(tailscaleOptions{authKey: testKey, authKeyFile: keyFile}), built: true, wantKey: testKey + "-file"},
		{name: "no key on first start", opts: on(tailscaleOptions{}), built: true, wantErr: "no auth key: set HEARTH_TS_AUTHKEY or --tailscale-authkey-file"},
		{name: "logged in needs no key", opts: on(tailscaleOptions{}), dataDir: loggedIn, built: true, wantKey: ""},
		{name: "key file readable by others", opts: on(tailscaleOptions{authKeyFile: openFile}), built: true, wantErr: "chmod 600"},
		{name: "missing key file", opts: on(tailscaleOptions{authKeyFile: filepath.Join(t.TempDir(), "nope")}), built: true, wantErr: "--tailscale-authkey-file"},
		{name: "bad hostname", opts: on(tailscaleOptions{hostname: "Hearth Hub", authKey: testKey}), built: true, wantErr: "--tailscale-hostname"},
		{name: "hostname with dash", opts: on(tailscaleOptions{hostname: "hearth-2", authKey: testKey}), built: true, wantKey: testKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := tt.dataDir
			if dataDir == "" {
				dataDir = t.TempDir()
			}
			cfg, err := tt.opts.resolve(dataDir, tt.built)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), "SecretPart") {
					t.Fatalf("error echoes the auth key: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantNil {
				if cfg != nil {
					t.Fatalf("cfg = %+v, want nil", cfg)
				}
				return
			}
			if cfg.authKey != tt.wantKey {
				t.Errorf("auth key %q, want %q", cfg.authKey, tt.wantKey)
			}
			info, err := os.Stat(cfg.dir)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o700 || cfg.dir != filepath.Join(dataDir, tailscaleDir) {
				t.Errorf("state dir %s mode %v, want <data-dir>/tailscale 0700", cfg.dir, info.Mode().Perm())
			}
		})
	}
}

// TestTailscaleFlags checks the precedence of flags over the environment.
func TestTailscaleFlags(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		args     []string
		want     tailscaleOptions
		wantErrs string
	}{
		{name: "defaults", want: tailscaleOptions{hostname: "hearth"}},
		{name: "env", env: map[string]string{
			"HEARTH_TAILSCALE": "true", "HEARTH_TAILSCALE_HOSTNAME": "lab", "HEARTH_TS_AUTHKEY": testKey,
			"HEARTH_TS_AUTHKEY_FILE": "/env.key",
		}, want: tailscaleOptions{enabled: true, hostname: "lab", authKey: testKey, authKeyFile: "/env.key"}},
		{
			name: "flags win", env: map[string]string{
				"HEARTH_TAILSCALE": "true", "HEARTH_TAILSCALE_HOSTNAME": "lab", "HEARTH_TS_AUTHKEY_FILE": "/env.key",
			}, args: []string{"--tailscale=false", "--tailscale-hostname", "nas", "--tailscale-authkey-file", "/flag.key"},
			want: tailscaleOptions{hostname: "nas", authKeyFile: "/flag.key"},
		},
		{name: "bad env bool", env: map[string]string{"HEARTH_TAILSCALE": "maybe"}, wantErrs: "HEARTH_TAILSCALE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"HEARTH_TAILSCALE", "HEARTH_TAILSCALE_HOSTNAME", "HEARTH_TS_AUTHKEY", "HEARTH_TS_AUTHKEY_FILE"} {
				t.Setenv(k, tt.env[k])
			}
			cmd := &cobra.Command{}
			var got tailscaleOptions
			addTailscaleFlags(cmd, &got)
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			err := got.fromEnv(cmd)
			if tt.wantErrs != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrs) {
					t.Fatalf("err = %v, want %q", err, tt.wantErrs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRedactKey(t *testing.T) {
	for _, tc := range []struct{ in, key string }{
		{"backend: invalid key " + testKey + " given", testKey},
		{"register: tskey-client-abcDEF123-xyz refused", ""},
		{"key " + "plainsecret", "plainsecret"},
	} {
		got := redactKey(tc.in, tc.key)
		if strings.Contains(got, "SecretPart") || strings.Contains(got, "abcDEF") || strings.Contains(got, "plainsecret") {
			t.Errorf("redactKey(%q) = %q, still holds the key", tc.in, got)
		}
		if !strings.Contains(got, "redacted") {
			t.Errorf("redactKey(%q) = %q, want a marker", tc.in, got)
		}
	}
}

// fakeNode is a tailnetNode on loopback: Listen binds 127.0.0.1 ports.
type fakeNode struct {
	upErr  error
	tlsErr error

	mu  sync.Mutex
	lns map[string]net.Listener
}

func (n *fakeNode) Up(context.Context) (string, []netip.Addr, error) {
	if n.upErr != nil {
		return "", nil, n.upErr
	}
	return "hearth.tail-scale.ts.net.", []netip.Addr{netip.MustParseAddr("100.64.0.7")}, nil
}

func (n *fakeNode) listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.lns == nil {
		n.lns = map[string]net.Listener{}
	}
	n.lns[addr] = ln
	return ln, nil
}

func (n *fakeNode) Listen(addr string) (net.Listener, error) { return n.listen(addr) }

func (n *fakeNode) ListenTLS(addr string) (net.Listener, error) {
	if n.tlsErr != nil {
		return nil, n.tlsErr
	}
	return n.listen(addr)
}

func (n *fakeNode) Close() error { return nil }

func (n *fakeNode) addr(port string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ln := n.lns[port]; ln != nil {
		return ln.Addr().String()
	}
	return ""
}

func waitTailnet(t *testing.T, tn *tailnet, state string) hub.TailnetStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st := tn.Status(); st.State == state {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tailnet state %q, want %q", tn.Status().State, state)
	return hub.TailnetStatus{}
}

func testServe(t *testing.T) tailnetServe {
	t.Helper()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	text := func(s string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, s) })
	}
	return tailnetServe{
		agentPort: "7443", httpPort: "7080", agent: text("agent"), ca: ca,
		hosts: []string{"nas.lan", "192.168.1.10"}, web: text("web"), ui: text("ui"),
	}
}

// TestTailnetServes checks what a hub serves on the tailnet: agents and the UI
// over TLS with a hub CA certificate that names the tailnet name and address,
// the plain HTTP listener, and the fallback when the tailnet has HTTPS off.
func TestTailnetServes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s := testServe(t)
	node := &fakeNode{tlsErr: errors.New("tsnet: you must enable HTTPS in the admin panel to proceed")}
	tn := newTailnet(tailnetConfig{hostname: "hearth"}, slog.New(slog.DiscardHandler))
	done := make(chan error, 1)
	go func() { done <- tn.run(ctx, node, s) }()
	st := waitTailnet(t, tn, hub.TailnetRunning)
	if st.DNSName != "hearth.tail-scale.ts.net" || len(st.IPs) != 1 || st.IPs[0] != "100.64.0.7" {
		t.Errorf("status %+v", st)
	}
	if st.URL != "https://hearth.tail-scale.ts.net:7443/" || st.AgentURL != "https://hearth.tail-scale.ts.net:7443" {
		t.Errorf("url %q agent url %q, want the hub CA's HTTPS port", st.URL, st.AgentURL)
	}
	if !strings.Contains(st.HTTPSNote, "enable HTTPS") {
		t.Errorf("https note %q", st.HTTPSNote)
	}
	if got := st.Hosts(); len(got) != 2 || got[0] != "hearth.tail-scale.ts.net" || got[1] != "100.64.0.7" {
		t.Errorf("hosts %v", got)
	}

	pool := x509.NewCertPool()
	pool.AddCert(s.ca.Cert())
	for _, name := range []string{"hearth.tail-scale.ts.net", "100.64.0.7", "nas.lan"} {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: name}}}
		res, err := c.Get("https://" + node.addr(":7443") + "/")
		if err != nil {
			t.Fatalf("TLS as %s: %v", name, err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if string(body) != "agent" {
			t.Errorf("TLS as %s: body %q", name, body)
		}
	}
	res, err := http.Get("http://" + node.addr(":7080") + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if string(body) != "web" {
		t.Errorf("plain HTTP body %q", body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("run: %v", err)
	}
}

// TestTailnetHTTPS checks the UI on 443 when the tailnet gives certificates.
func TestTailnetHTTPS(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	node := &fakeNode{}
	tn := newTailnet(tailnetConfig{hostname: "hearth"}, slog.New(slog.DiscardHandler))
	go func() { _ = tn.run(ctx, node, testServe(t)) }()
	st := waitTailnet(t, tn, hub.TailnetRunning)
	if st.URL != "https://hearth.tail-scale.ts.net/" || st.HTTPSNote != "" {
		t.Errorf("url %q note %q, want 443", st.URL, st.HTTPSNote)
	}
	res, err := http.Get("http://" + node.addr(":443") + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if string(body) != "ui" {
		t.Errorf("443 body %q", body)
	}
}

// TestTailnetRefused checks that a node the tailnet refuses leaves the hub
// running, with the reason in its status and without the auth key.
func TestTailnetRefused(t *testing.T) {
	node := &fakeNode{upErr: errors.New("tsnet.Up: backend: invalid key: " + testKey)}
	tn := newTailnet(tailnetConfig{hostname: "hearth", authKey: testKey}, slog.New(slog.DiscardHandler))
	if err := tn.run(t.Context(), node, testServe(t)); err != nil {
		t.Fatalf("run = %v, want nil: the hub runs on", err)
	}
	st := tn.Status()
	if st.State != hub.TailnetError || !strings.Contains(st.Error, "invalid key") || strings.Contains(st.Error, "SecretPart") {
		t.Errorf("status %+v", st)
	}
	if st.Hosts() != nil {
		t.Errorf("hosts %v, want none while not running", st.Hosts())
	}
}
