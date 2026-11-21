// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"errors"
	"testing"
	"time"
)

func TestKeyProof(t *testing.T) {
	now := time.Now()
	ca, err := LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("for this")
	sig, err := ca.ProveKey(FingerprintHex(ca.Cert()), msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyProof(ca.Cert(), msg, sig); err != nil {
		t.Fatalf("a valid proof: %v", err)
	}
	for name, tc := range map[string]struct {
		msg, sig []byte
		ca       *CA
	}{
		"another message": {[]byte("for that"), sig, ca},
		"another CA":      {msg, sig, other},
		"no proof":        {msg, nil, ca},
	} {
		if err := VerifyKeyProof(tc.ca.Cert(), tc.msg, tc.sig); !errors.Is(err, ErrBadKeyProof) {
			t.Errorf("%s: %v, want ErrBadKeyProof", name, err)
		}
	}
	if _, err := ca.ProveKey(FingerprintHex(other.Cert()), msg); !errors.Is(err, ErrNoCAKey) {
		t.Errorf("proof for a CA not held: %v, want ErrNoCAKey", err)
	}
	dir := t.TempDir()
	if err := InstallCACert(dir, ca.Cert().Raw, ca.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	keyless, err := LoadCA(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyless.ProveKey(FingerprintHex(ca.Cert()), msg); !errors.Is(err, ErrNoCAKey) {
		t.Errorf("proof without the key: %v, want ErrNoCAKey", err)
	}
}
