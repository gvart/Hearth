// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/release"
)

func TestRun(t *testing.T) {
	t.Parallel()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	trusted, _ := key.Public().(ed25519.PublicKey)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(seed)
	file := filepath.Join(t.TempDir(), "checksums.txt")
	body := []byte("abc  hearth_1.0.0_linux_amd64.tar.gz\n")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		args    []string
		seed    string
		trusted ed25519.PublicKey
		wantErr string
	}{
		{name: "no file", seed: b64, trusted: trusted, wantErr: "usage"},
		{name: "empty key", args: []string{file}, trusted: trusted, wantErr: "is empty"},
		{name: "not base64", args: []string{file}, seed: "%%%", trusted: trusted, wantErr: "not the base64"},
		{name: "short seed", args: []string{file}, seed: base64.StdEncoding.EncodeToString(seed[:16]), trusted: trusted, wantErr: "not the base64"},
		{name: "untrusted key", args: []string{file}, seed: b64, trusted: other, wantErr: "not the key"},
		{name: "missing file", args: []string{file + ".none"}, seed: b64, trusted: trusted, wantErr: "no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := run(tt.args, tt.seed, tt.trusted)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("run = %v, want an error with %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), b64) {
				t.Errorf("the error quotes the key: %v", err)
			}
		})
	}

	if err := run([]string{file}, b64, trusted); err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(file + release.SignatureSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.Verify(trusted, body, sig); err != nil {
		t.Errorf("the written signature does not verify: %v", err)
	}
}
