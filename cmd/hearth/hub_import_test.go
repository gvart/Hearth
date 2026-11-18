// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLeaseSources(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "pihole.pass")
	open := filepath.Join(dir, "open.pass")
	leases := filepath.Join(dir, "dnsmasq.leases")
	for p, mode := range map[string]os.FileMode{secret: 0o600, open: 0o644, leases: 0o644} {
		if err := os.WriteFile(p, []byte("app-pass\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name    string
		opts    hubOptions
		sources int
		wantErr string
	}{
		{"none", hubOptions{}, 0, ""},
		{"pihole env password", hubOptions{piholeURL: "http://pi.hole", piholePassword: "x"}, 1, ""},
		{"pihole password file", hubOptions{piholeURL: "http://pi.hole", piholePasswordFile: secret}, 1, ""},
		{"lease files", hubOptions{dhcpLeases: []string{leases, leases}}, 2, ""},
		{"both passwords", hubOptions{piholeURL: "http://pi.hole", piholePassword: "x", piholePasswordFile: secret}, 0, "not both"},
		{"password file without url", hubOptions{piholePasswordFile: secret}, 0, "needs --pihole-url"},
		{"bad url", hubOptions{piholeURL: "pi.hole"}, 0, "--pihole-url"},
		{"missing lease file", hubOptions{dhcpLeases: []string{filepath.Join(dir, "nope")}}, 0, "--dhcp-leases"},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name    string
			opts    hubOptions
			sources int
			wantErr string
		}{"world-readable password file", hubOptions{piholeURL: "http://pi.hole", piholePasswordFile: open}, 0, "chmod 600"})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := leaseSources(tt.opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || len(got) != tt.sources {
				t.Fatalf("leaseSources = %d sources, %v; want %d", len(got), err, tt.sources)
			}
		})
	}
}
