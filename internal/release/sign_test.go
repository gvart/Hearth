// SPDX-License-Identifier: AGPL-3.0-only

package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestTrustedKeyIsTheReleaseKey(t *testing.T) {
	t.Parallel()
	k, err := TrustedKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(k); got != PublicKey {
		t.Errorf("trusted key = %s, want %s", got, PublicKey)
	}
}

func TestSignVerify(t *testing.T) {
	t.Parallel()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	key, err := ParseSeed(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("0123  hearth_1.0.0_linux_amd64.tar.gz\n")
	sig := Sign(key, body)
	if err := Verify(pub, body, sig); err != nil {
		t.Fatalf("Verify of a good signature = %v", err)
	}
	tests := []struct {
		name    string
		key     ed25519.PublicKey
		body    []byte
		sig     []byte
		wantErr string
	}{
		{name: "another key", key: other, body: body, sig: sig, wantErr: "does not verify"},
		{name: "changed checksums", key: pub, body: append([]byte("x"), body...), sig: sig, wantErr: "does not verify"},
		{name: "not base64", key: pub, body: body, sig: []byte("%%%"), wantErr: "malformed"},
		{name: "empty", key: pub, body: body, sig: nil, wantErr: "malformed"},
		{name: "short", key: pub, body: body, sig: []byte(base64.StdEncoding.EncodeToString([]byte("short"))), wantErr: "malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := Verify(tt.key, tt.body, tt.sig); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Verify = %v, want an error with %q", err, tt.wantErr)
			}
		})
	}
	if _, err := ParsePublicKey("abc"); err == nil {
		t.Error("ParsePublicKey of a short key = nil error")
	}
}
