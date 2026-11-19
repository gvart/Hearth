// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

// The CAs and the certificate a Welcome carries are taken only as a hub CA
// rotation hands them out: a hub, or someone holding a hub's certificate,
// cannot make an agent trust a CA of its own.
func TestCheckRenewal(t *testing.T) {
	now := time.Now()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	evil, err := pki.LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pki.LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	certOf := func(c *pki.CA) []byte {
		t.Helper()
		leaf, err := c.SignClientKey(key.Public(), "pi", now)
		if err != nil {
			t.Fatal(err)
		}
		return pki.EncodeCertPEM(leaf)
	}
	pemOf := func(cs ...*x509.Certificate) []byte {
		var out []byte
		for _, c := range cs {
			out = append(out, pki.EncodeCertPEM(c)...)
		}
		return out
	}
	oldCA := ca.Cert()
	original := certOf(ca)
	newCA, err := ca.GenerateNext(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.TrustNext(newCA); err != nil {
		t.Fatal(err)
	}
	renewed := certOf(ca) // the signer is the new CA during the rotation
	otherKey, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	notMine, err := ca.SignClientKey(otherKey.Public(), "pi", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		cur, bundle  []byte
		cert, held   []byte
		root         *x509.Certificate
		wantAccepted bool
	}{
		{"the rotation's renewal", pemOf(oldCA), pemOf(oldCA, newCA), renewed, original, oldCA, true},
		{"the renewal over a hub serving the new CA", pemOf(oldCA), pemOf(newCA, oldCA), renewed, original, newCA, true},
		{"the finish drops the old CA", pemOf(oldCA, newCA), pemOf(newCA), nil, renewed, newCA, true},
		{"a hub drops the CA of the agent's certificate", pemOf(oldCA, newCA), pemOf(oldCA), nil, renewed, oldCA, false},
		{"the abort drops the new CA of an agent not renewed", pemOf(oldCA, newCA), pemOf(oldCA), nil, original, oldCA, true},
		{"the same CAs in another order", pemOf(oldCA, newCA), pemOf(newCA, oldCA), nil, renewed, oldCA, true},
		{"a renewal alone", pemOf(oldCA, newCA), nil, renewed, original, newCA, true},
		{"a CA added without a renewal", pemOf(oldCA), pemOf(oldCA, evil.Cert()), nil, original, oldCA, false},
		{"a CA added that leaves out the verifying one", pemOf(oldCA), pemOf(evil.Cert()), certOf(evil), original, oldCA, false},
		{"a CA added with no verified hub", pemOf(oldCA), pemOf(oldCA, evil.Cert()), certOf(evil), original, nil, false},
		{"three CAs", pemOf(oldCA), pemOf(oldCA, newCA, evil.Cert()), renewed, original, oldCA, false},
		{"a renewal no CA in the bundle issued", pemOf(oldCA), pemOf(oldCA, evil.Cert()), certOf(other), original, oldCA, false},
		{"a renewal for another key", pemOf(oldCA), pemOf(oldCA, newCA), pki.EncodeCertPEM(notMine), original, oldCA, false},
		{"a renewal of an untrusted CA", pemOf(oldCA, newCA), nil, certOf(evil), original, newCA, false},
		{"a bundle that is not CAs", pemOf(oldCA), renewed, renewed, original, oldCA, false},
		{"a bundle of garbage", pemOf(oldCA), []byte("not pem"), nil, original, oldCA, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRenewal(tc.cur, tc.bundle, tc.cert, keyPEM, tc.held, tc.root)
			if (err == nil) != tc.wantAccepted {
				t.Errorf("checkRenewal = %v, want accepted %v", err, tc.wantAccepted)
			}
		})
	}
}
