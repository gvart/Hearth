// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func clientCert(t *testing.T, ca *CA, id string) *x509.Certificate {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key, id)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.SignClientCSR(csr, id, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func verifies(cert *x509.Certificate, pool *x509.CertPool) bool {
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// A rotation on one hub: the leader generates the next CA, a member trusts
// it and installs its key; both CAs are trusted until the finish, which
// leaves only the next CA, in ca.crt and ca.key.
func TestCARotation(t *testing.T) {
	leader, leaderDir := newCA(t)
	oldCert := leader.Cert()
	oldKey, err := os.ReadFile(filepath.Join(leaderDir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	oldClient := clientCert(t, leader, "pi")

	_, memberDir := newCA(t)
	// The member is a copy of the leader's CA, as after a join.
	for _, f := range []string{CACertFile, CAKeyFile} {
		b, err := os.ReadFile(filepath.Join(leaderDir, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(memberDir, f), b, 0o600); err != nil { //nolint:gosec // a test temp dir
			t.Fatal(err)
		}
	}
	member, err := LoadOrCreateCA(memberDir, now)
	if err != nil {
		t.Fatal(err)
	}

	changes := 0
	leader.OnChange(func() { changes++ })
	next, err := leader.GenerateNext(now)
	if err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Errorf("OnChange called %d times, want 1", changes)
	}
	if _, err := leader.GenerateNext(now); !errors.Is(err, ErrOtherNextCA) {
		t.Errorf("GenerateNext twice = %v, want ErrOtherNextCA", err)
	}
	if !leader.Cert().Equal(oldCert) || !leader.SignerCert().Equal(next) || !leader.HasNextKey() {
		t.Fatal("after GenerateNext: want the old CA serving and the next one signing")
	}
	srv, err := leader.IssueServerCert([]string{"hub"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Leaf.CheckSignatureFrom(oldCert) != nil {
		t.Error("server certificate not from the old CA before the cutover")
	}
	newClient := clientCert(t, leader, "pi")
	if leader.IssuerOf(newClient) == nil || !leader.IssuerOf(newClient).Equal(next) {
		t.Error("a new client certificate is not from the next CA")
	}
	for name, c := range map[string]*x509.Certificate{"old": oldClient, "new": newClient} {
		if !verifies(c, leader.Pool()) {
			t.Errorf("%s client certificate not trusted during the rotation", name)
		}
	}

	// The member trusts the next CA before it has its key, and signs with
	// the old one until then.
	if err := member.TrustNext(next); err != nil {
		t.Fatal(err)
	}
	if member.HasNextKey() || !member.SignerCert().Equal(oldCert) || !verifies(newClient, member.Pool()) {
		t.Fatal("member after TrustNext: want the next CA trusted, not signing")
	}
	other, _ := newCA(t)
	otherKey, err := other.KeyDER()
	if err != nil {
		t.Fatal(err)
	}
	if err := member.InstallNextKey(otherKey); err == nil {
		t.Fatal("InstallNextKey with another CA's key succeeded")
	}
	if err := member.InstallNextKey([]byte("junk")); err == nil {
		t.Fatal("InstallNextKey with a malformed key succeeded")
	}
	if err := member.TrustNext(other.Cert()); !errors.Is(err, ErrOtherNextCA) {
		t.Errorf("TrustNext(another) = %v, want ErrOtherNextCA", err)
	}
	keyDER, err := leader.NextKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	if err := member.InstallNextKey(keyDER); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(memberDir, NextCAKeyFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("next CA key file: %v, %v; want mode 0600", fi, err)
	}
	// A restart in the window loads both CAs.
	reloaded, err := LoadOrCreateCA(memberDir, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.HasNextKey() || !reloaded.Next().Equal(next) || !reloaded.Cert().Equal(oldCert) {
		t.Fatal("reloaded member: want the old CA serving and the next one with its key")
	}

	// Sealing secrets: the serving CA's key first, then the other.
	ders, err := member.KeyDERs()
	if err != nil || len(ders) != 2 || !bytes.Equal(ders[1], keyDER) {
		t.Fatalf("KeyDERs = %d keys, %v; want the next CA's second before the cutover", len(ders), err)
	}

	if err := member.Cutover(); err != nil {
		t.Fatal(err)
	}
	if ders, err := member.KeyDERs(); err != nil || len(ders) != 2 || !bytes.Equal(ders[0], keyDER) {
		t.Fatalf("KeyDERs after the cutover = %d keys, %v; want the next CA's first", len(ders), err)
	}
	if !member.Cert().Equal(next) || !member.TrustedCerts()[0].Equal(next) {
		t.Error("after the cutover the next CA is not the one served")
	}
	srv, err = member.IssueServerCert([]string{"hub"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Leaf.CheckSignatureFrom(next) != nil {
		t.Error("server certificate not from the next CA after the cutover")
	}

	if err := member.Finish(); err != nil {
		t.Fatal(err)
	}
	if !member.Cert().Equal(next) || member.Next() != nil || len(member.TrustedCerts()) != 1 {
		t.Fatal("after Finish: want the next CA alone")
	}
	if verifies(oldClient, member.Pool()) {
		t.Error("an old-CA certificate is trusted after the finish")
	}
	if !verifies(newClient, member.Pool()) {
		t.Error("a next-CA certificate is not trusted after the finish")
	}
	// The core threat: whoever kept the old key mints a certificate, and it
	// is not trusted.
	thief, err := LoadOrCreateCA(leaderDir, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := thief.DropNext(); err != nil {
		t.Fatal(err)
	}
	if minted := clientCert(t, thief, "pi"); verifies(minted, member.Pool()) || member.IssuerOf(minted) != nil {
		t.Error("a certificate minted with the old key after the finish is trusted")
	}
	for _, f := range []string{NextCACertFile, NextCAKeyFile} {
		if _, err := os.Stat(filepath.Join(memberDir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left after Finish: %v", f, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(memberDir, CAKeyFile)); bytes.Equal(b, oldKey) {
		t.Error("the old key is still in ca.key after Finish")
	}
	reloaded, err = LoadOrCreateCA(memberDir, now)
	if err != nil || !reloaded.Cert().Equal(next) || reloaded.Next() != nil {
		t.Fatalf("reloaded after Finish: %v", err)
	}
}

// A finish interrupted after the certificate's rename is completed on load;
// a key and certificate that do not match are refused.
func TestCARotationRecovery(t *testing.T) {
	ca, dir := newCA(t)
	next, err := ca.GenerateNext(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, NextCACertFile), filepath.Join(dir, CACertFile)); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateCA(dir, now)
	if err != nil {
		t.Fatalf("load after an interrupted finish: %v", err)
	}
	if !got.Cert().Equal(next) || got.Next() != nil {
		t.Error("the interrupted finish was not completed")
	}

	// A next certificate with another CA's key is refused.
	if _, err := got.GenerateNext(now); err != nil {
		t.Fatal(err)
	}
	_, otherDir := newCA(t)
	b, err := os.ReadFile(filepath.Join(otherDir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, NextCAKeyFile), b, 0o600); err != nil { //nolint:gosec // a test temp dir
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir, now); err == nil {
		t.Error("a next CA whose key does not match its certificate loaded")
	}

	// DropNext removes what an uncommitted rotation left.
	if err := os.Remove(filepath.Join(dir, NextCAKeyFile)); err != nil {
		t.Fatal(err)
	}
	ca, err = LoadOrCreateCA(dir, now)
	if err != nil || ca.Next() == nil || ca.HasNextKey() {
		t.Fatalf("a next certificate without its key: %v, want loaded without the key", err)
	}
	if err := ca.Cutover(); !errors.Is(err, ErrNoNextCA) {
		t.Errorf("Cutover without the next key = %v, want ErrNoNextCA", err)
	}
	if err := ca.DropNext(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, NextCACertFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("next certificate left after DropNext: %v", err)
	}
}
