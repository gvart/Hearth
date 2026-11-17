// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestJoinTokenKindsDoNotMix(t *testing.T) {
	ca, _ := newCA(t)
	tok, err := NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	s := tok.EncodeJoin()
	if !strings.HasPrefix(s, "hearthj1.") {
		t.Fatalf("EncodeJoin = %q, want hearthj1. prefix", s)
	}
	got, err := ParseJoinToken(s)
	if err != nil || got != tok {
		t.Fatalf("ParseJoinToken = %v, %v", got, err)
	}
	if _, err := ParseToken(s); err == nil {
		t.Error("ParseToken accepted a join token")
	}
	if _, err := ParseJoinToken(tok.Encode()); err == nil {
		t.Error("ParseJoinToken accepted an enrollment token")
	}
}

func TestSignHubCSR(t *testing.T) {
	ca, _ := newCA(t)
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.SignHubCSR(csr, "hub-a", now)
	if err != nil {
		t.Fatalf("SignHubCSR: %v", err)
	}
	if id, err := HubNodeID(cert); err != nil || id != "hub-a" {
		t.Errorf("HubNodeID = %q, %v", id, err)
	}
	if _, err := DeviceID(cert); err == nil {
		t.Error("a hub certificate carries a device ID")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert())
	for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{eku}}); err != nil {
			t.Errorf("verify for %v: %v", eku, err)
		}
	}
	// A device certificate is not a hub certificate.
	dev, err := ca.SignClientCSR(csr, "pi", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HubNodeID(dev); err == nil {
		t.Error("a device certificate carries a hub node ID")
	}
	if _, err := ca.SignHubCSR([]byte("junk"), "hub-a", now); err == nil {
		t.Error("SignHubCSR accepted a malformed CSR")
	}
}

func TestInstallCA(t *testing.T) {
	ca, _ := newCA(t)
	keyDER, err := ca.KeyDER()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := newCA(t)
	otherKey, err := other.KeyDER()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong fingerprint", func(t *testing.T) {
		dir := t.TempDir()
		err := InstallCA(dir, ca.Cert().Raw, keyDER, other.Fingerprint())
		if !errors.Is(err, ErrFingerprintMismatch) {
			t.Fatalf("err = %v, want ErrFingerprintMismatch", err)
		}
		if _, err := os.Stat(filepath.Join(dir, CAKeyFile)); !errors.Is(err, os.ErrNotExist) {
			t.Error("key written despite the mismatch")
		}
	})
	t.Run("key of another CA", func(t *testing.T) {
		if err := InstallCA(t.TempDir(), ca.Cert().Raw, otherKey, ca.Fingerprint()); err == nil {
			t.Fatal("accepted a key that does not match the certificate")
		}
	})
	t.Run("ok", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "hub")
		if err := InstallCA(dir, ca.Cert().Raw, keyDER, ca.Fingerprint()); err != nil {
			t.Fatalf("InstallCA: %v", err)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filepath.Join(dir, CAKeyFile))
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("ca.key mode = %o, want 600", perm)
			}
		}
		loaded, err := LoadOrCreateCA(dir, now)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Fingerprint() != ca.Fingerprint() {
			t.Error("installed CA differs")
		}
		if err := InstallCA(dir, ca.Cert().Raw, keyDER, ca.Fingerprint()); err == nil {
			t.Error("InstallCA overwrote an existing CA")
		}
	})
}
