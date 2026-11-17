// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var now = time.Now().Truncate(time.Second) // x509 times have second precision

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "hub")
	ca, err := LoadOrCreateCA(dir, now)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	return ca, dir
}

func TestLoadOrCreateCA(t *testing.T) {
	ca, dir := newCA(t)

	if runtime.GOOS != "windows" {
		for file, want := range map[string]os.FileMode{CAKeyFile: 0o600, CACertFile: 0o644} {
			fi, err := os.Stat(filepath.Join(dir, file))
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Perm(); got != want {
				t.Errorf("%s mode = %o, want %o", file, got, want)
			}
		}
	}
	if !ca.Cert().IsCA {
		t.Error("CA cert is not a CA")
	}

	again, err := LoadOrCreateCA(dir, now)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.Fingerprint() != ca.Fingerprint() {
		t.Error("reload produced a different CA")
	}
	cert, err := LoadCACert(dir)
	if err != nil || Fingerprint(cert) != ca.Fingerprint() {
		t.Errorf("LoadCACert = %v, %v; want the same CA", cert, err)
	}

	if err := os.Remove(filepath.Join(dir, CAKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir, now); err == nil {
		t.Error("cert without key: want error, not a silently regenerated CA")
	}
}

func TestSignClientCSR(t *testing.T) {
	ca, _ := newCA(t)
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key, "i-am-someone-else")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := ca.SignClientCSR(csr, "dev-1", now)
	if err != nil {
		t.Fatalf("SignClientCSR: %v", err)
	}
	if id, err := DeviceID(cert); err != nil || id != "dev-1" {
		t.Errorf("DeviceID = %q, %v; want dev-1 (CSR subject must be ignored)", id, err)
	}
	if got := cert.NotAfter.Sub(now); got != ClientCertValidity {
		t.Errorf("validity = %v, want %v", got, ClientCertValidity)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert())
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("client cert does not verify under CA: %v", err)
	}

	bad := []struct {
		name string
		csr  []byte
	}{
		{"garbage", []byte("not a csr")},
		{"tampered signature", append(append([]byte{}, csr[:len(csr)-1]...), csr[len(csr)-1]^0xff)},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ca.SignClientCSR(tt.csr, "dev-1", now); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestDeviceIDMissing(t *testing.T) {
	ca, _ := newCA(t)
	if _, err := DeviceID(ca.Cert()); err == nil {
		t.Error("CA cert has no device URI: want error")
	}
}

func TestTokenRoundTrip(t *testing.T) {
	ca, _ := newCA(t)
	tok, err := NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	s := tok.Encode()
	if !strings.HasPrefix(s, "hearth1.") {
		t.Errorf("Encode = %q, want hearth1. prefix", s)
	}
	got, err := ParseToken(s)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if got != tok {
		t.Error("round trip changed the token")
	}
	for _, leaked := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %+v %s", tok, tok, tok), tok.LogValue().String()} {
		if strings.Contains(leaked, tok.Secret) {
			t.Errorf("formatted token leaks secret: %q", leaked)
		}
	}
}

func TestParseTokenRejects(t *testing.T) {
	ca, _ := newCA(t)
	tok, err := NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok.Encode(), ".")
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"wrong prefix", "hearth2." + parts[1] + "." + parts[2]},
		{"missing part", parts[0] + "." + parts[1]},
		{"extra part", tok.Encode() + ".x"},
		{"short secret", parts[0] + ".abc." + parts[2]},
		{"bad base64", parts[0] + ".!!!." + parts[2]},
		{"short fingerprint", parts[0] + "." + parts[1] + ".abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseToken(tt.in)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), parts[1]) {
				t.Errorf("error leaks secret: %v", err)
			}
		})
	}
}

func TestVerifyPinned(t *testing.T) {
	ca, _ := newCA(t)
	other, _ := newCA(t)
	srv, err := ca.IssueServerCert([]string{"hub.lan", "10.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	chain := make([]*x509.Certificate, len(srv.Certificate))
	for i, der := range srv.Certificate {
		if chain[i], err = x509.ParseCertificate(der); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name    string
		chain   []*x509.Certificate
		fp      [32]byte
		host    string
		wantErr error
		ok      bool
	}{
		{name: "dns name", chain: chain, fp: ca.Fingerprint(), host: "hub.lan", ok: true},
		{name: "ip", chain: chain, fp: ca.Fingerprint(), host: "10.0.0.1", ok: true},
		{name: "wrong fingerprint", chain: chain, fp: other.Fingerprint(), host: "hub.lan", wantErr: ErrFingerprintMismatch},
		{name: "host not in SANs", chain: chain, fp: ca.Fingerprint(), host: "evil.lan"},
		{name: "leaf only", chain: chain[:1], fp: ca.Fingerprint(), host: "hub.lan", wantErr: ErrFingerprintMismatch},
		{name: "empty", fp: ca.Fingerprint(), host: "hub.lan"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyPinned(tt.chain, tt.fp, tt.host)
			if tt.ok {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
