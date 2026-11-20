// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// A member of an AP cluster that is not a master holds the CA certificate
// but not its key (docs/design/ap-cluster.md §6, §9): it verifies hub and
// device certificates and signs nothing. The key arrives when the member is
// promoted to master and is deleted when it is demoted.

// ErrNoCAKey is returned by what needs the CA key on a hub without it.
var ErrNoCAKey = errors.New("this hub does not hold the CA key")

// LoadCA loads the CA from dir like LoadOrCreateCA, and also a CA whose
// certificate is there without its key: a CA that signs nothing (HasKey is
// false). With neither file it creates a CA, as LoadOrCreateCA does.
func LoadCA(dir string, now time.Time) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr != nil || !errors.Is(keyErr, os.ErrNotExist) {
		return LoadOrCreateCA(dir, now)
	}
	cert, err := LoadCACert(dir)
	if err != nil {
		return nil, err
	}
	return caFrom(dir, keyPair{cert: cert}, nil), nil
}

// HasKey reports whether the hub holds the key of the CA it serves.
func (c *CA) HasKey() bool { return c.state().serving().key != nil }

// SetKey installs keyDER, the PKCS #8 key of the CA this hub serves, in its
// data dir (ca.key, 0600) and starts signing with it. It refuses a key of
// another CA and a hub that holds a key already.
func (c *CA) SetKey(keyDER []byte) error {
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return errors.New("install CA key: malformed key") // never echo key material
	}
	key, ok := k.(crypto.Signer)
	if !ok {
		return fmt.Errorf("install CA key: unsupported key type %T", k)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state()
	cur := s.cur
	switch {
	case cur.key != nil:
		return errors.New("install CA key: this hub holds the CA key already")
	case !keyMatches(cur.cert, key):
		return errors.New("install CA key: the key is not this hub's CA's")
	}
	if c.dir != "" {
		if err := writeFile(filepath.Join(c.dir, CAKeyFile),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
			return fmt.Errorf("install CA key: %w", err)
		}
	}
	cur.key = key
	c.st.Store(newState(cur, s.next, s.active, s.cutover))
	return nil
}

// DropKey deletes the CA key from the data dir and from memory: the hub
// signs nothing any more. A hub without the key is left as it is.
func (c *CA) DropKey() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dir != "" {
		if err := os.Remove(filepath.Join(c.dir, CAKeyFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete CA key: %w", err)
		}
	}
	s := c.state()
	cur := s.cur
	cur.key = nil
	c.st.Store(newState(cur, s.next, s.active, s.cutover))
	return nil
}

// InstallCACert writes a CA certificate received from a cluster peer into
// dir (ca.crt, 0644), without its key, refusing to overwrite it. It must
// have fingerprint want.
func InstallCACert(dir string, certDER []byte, want [sha256.Size]byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("install CA: parse cert: %w", err)
	}
	if Fingerprint(cert) != want {
		return fmt.Errorf("install CA: %w", ErrFingerprintMismatch)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	if err := WriteCertFile(filepath.Join(dir, CACertFile), cert); err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	return nil
}
