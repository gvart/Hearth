// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Hub CA rotation (docs/cluster.md, "Rotating the hub CA").
//
// A rotation adds a next CA next to the current one: ca.next.crt and
// ca.next.key in the data dir. From then on the hub trusts both, signs new
// certificates with the next CA and keeps serving TLS with certificates of
// the current one, so agents that only know it can still connect and learn
// the next one. At the cutover the hub serves certificates of the next CA.
// Finish renames the next CA over the current one, which deletes the
// current key, and only the next CA is trusted from then on.

// File names of the next CA inside a data dir.
const (
	NextCACertFile = "ca.next.crt"
	NextCAKeyFile  = "ca.next.key"
)

// Errors of the rotation methods.
var (
	// ErrNoNextCA refuses a step that needs a next CA, or its key.
	ErrNoNextCA = errors.New("no next CA (or not its key) on this hub")
	// ErrOtherNextCA refuses a next CA when another one is already here.
	ErrOtherNextCA = errors.New("this hub already has another next CA")
)

// recoverFinish completes a Finish interrupted between renaming the next
// certificate and the next key: ca.crt is then the next CA's and ca.next.key
// its key. An orphaned ca.next.key that is not ca.crt's is left alone.
func recoverFinish(dir string) error {
	nextKey := filepath.Join(dir, NextCAKeyFile)
	if _, err := os.Stat(filepath.Join(dir, NextCACertFile)); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if _, err := os.Stat(nextKey); err != nil {
		return nil
	}
	cert, err := LoadCACert(dir)
	if err != nil {
		return nil //nolint:nilerr // no complete CA: LoadOrCreateCA reports it
	}
	key, err := ReadKey(nextKey)
	if err != nil || !keyMatches(cert, key) {
		return nil //nolint:nilerr // not the interrupted finish
	}
	if err := os.Rename(nextKey, filepath.Join(dir, CAKeyFile)); err != nil {
		return fmt.Errorf("complete the CA rotation: %w", err)
	}
	syncDir(dir)
	return nil
}

// loadNext loads the next CA from dir, if there is one; its key may be
// missing (a certificate written before the key).
func loadNext(dir string) (*keyPair, error) {
	certPath, keyPath := filepath.Join(dir, NextCACertFile), filepath.Join(dir, NextCAKeyFile)
	b, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("read next CA cert: %w", err)
	}
	cert, err := ParseCertPEM(b)
	if err != nil {
		return nil, fmt.Errorf("next CA: %w", err)
	}
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		return &keyPair{cert: cert}, nil
	}
	kp, err := loadKeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("next CA: %w", err)
	}
	return &kp, nil
}

// OnChange registers fn to be called after every change of the CA's state:
// a next CA trusted or installed, the cutover, the finish. Calls run on the
// goroutine that made the change; fn must not block for long.
func (c *CA) OnChange(fn func()) {
	c.onChangeMu.Lock()
	defer c.onChangeMu.Unlock()
	c.onChange = append(c.onChange, fn)
}

func (c *CA) changed() {
	c.onChangeMu.Lock()
	fns := append([]func(){}, c.onChange...)
	c.onChangeMu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// Pool returns the CA certificates this hub trusts: the current CA and, while
// a rotation runs, the next one.
func (c *CA) Pool() *x509.CertPool { return c.state().pool }

// TrustedCerts returns the CA certificates this hub trusts, the one Cert
// returns first.
func (c *CA) TrustedCerts() []*x509.Certificate {
	s := c.state()
	out := []*x509.Certificate{s.serving().cert}
	if s.next != nil {
		if s.cutover {
			out = append(out, s.cur.cert)
		} else {
			out = append(out, s.next.cert)
		}
	}
	return out
}

// SignerCert returns the CA certificate new certificates are signed with: the
// next CA's once this hub holds its key.
func (c *CA) SignerCert() *x509.Certificate { return c.state().signer().cert }

// Next returns the next CA's certificate, or nil outside a rotation.
func (c *CA) Next() *x509.Certificate {
	if n := c.state().next; n != nil {
		return n.cert
	}
	return nil
}

// HasNextKey reports whether this hub holds the next CA's key.
func (c *CA) HasNextKey() bool {
	n := c.state().next
	return n != nil && n.key != nil
}

// CutOver reports whether the hub serves certificates of the next CA.
func (c *CA) CutOver() bool { return c.state().cutover }

// IssuerOf returns the trusted CA certificate that signed cert, or nil.
func (c *CA) IssuerOf(cert *x509.Certificate) *x509.Certificate {
	s := c.state()
	for _, kp := range []*keyPair{&s.cur, s.next} {
		if kp != nil && cert.CheckSignatureFrom(kp.cert) == nil {
			return kp.cert
		}
	}
	return nil
}

// KeyDERs returns the private keys of the CAs this hub holds as PKCS#8 DER,
// the serving CA's first: the secrets sealing keys are derived from. Secrets
// are sealed with the serving CA's key, which every hub holds by the cutover,
// and opened with either. Never log or persist them.
func (c *CA) KeyDERs() ([][]byte, error) {
	s := c.state()
	pairs := []keyPair{s.serving()}
	switch {
	case s.next == nil || s.next.key == nil:
	case s.cutover:
		pairs = append(pairs, s.cur)
	default:
		pairs = append(pairs, *s.next)
	}
	out := make([][]byte, 0, len(pairs))
	for _, kp := range pairs {
		der, err := x509.MarshalPKCS8PrivateKey(kp.key)
		if err != nil {
			return nil, fmt.Errorf("encode CA key: %w", err)
		}
		out = append(out, der)
	}
	return out, nil
}

// NextKeyDER returns the next CA's private key as PKCS#8 DER, to hand to a
// member over the pinned cluster channel. Never log or persist it.
func (c *CA) NextKeyDER() ([]byte, error) {
	n := c.state().next
	if n == nil || n.key == nil {
		return nil, ErrNoNextCA
	}
	der, err := x509.MarshalPKCS8PrivateKey(n.key)
	if err != nil {
		return nil, fmt.Errorf("encode next CA key: %w", err)
	}
	return der, nil
}

// GenerateNext creates a next CA and writes it into the data dir (the key at
// 0600) before it is used. It fails with ErrOtherNextCA if there is one.
func (c *CA) GenerateNext(now time.Time) (*x509.Certificate, error) {
	c.mu.Lock()
	s := c.state()
	if s.next != nil {
		c.mu.Unlock()
		return nil, ErrOtherNextCA
	}
	kp, err := generateKeyPair(now)
	if err == nil {
		err = c.writeNext(kp)
	}
	if err == nil {
		c.st.Store(newState(s.cur, &kp, false))
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c.changed()
	return kp.cert, nil
}

// TrustNext trusts cert as the next CA before this hub holds its key, so it
// accepts certificates the next CA signed. Trusting the next CA it has is a
// no-op; another one fails with ErrOtherNextCA.
func (c *CA) TrustNext(cert *x509.Certificate) error {
	c.mu.Lock()
	s := c.state()
	switch {
	case s.next != nil && s.next.cert.Equal(cert):
		c.mu.Unlock()
		return nil
	case s.next != nil:
		c.mu.Unlock()
		return ErrOtherNextCA
	case !cert.IsCA:
		c.mu.Unlock()
		return errors.New("next CA: not a CA certificate")
	}
	c.st.Store(newState(s.cur, &keyPair{cert: cert}, false))
	c.mu.Unlock()
	c.changed()
	return nil
}

// InstallNextKey installs the next CA's key, received from a cluster member,
// and writes the next CA into the data dir (the key at 0600). The key must
// belong to the next CA TrustNext set.
func (c *CA) InstallNextKey(keyDER []byte) error {
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return errors.New("next CA: malformed key") // never echo key material
	}
	key, ok := k.(crypto.Signer)
	if !ok {
		return fmt.Errorf("next CA: unsupported key type %T", k)
	}
	c.mu.Lock()
	s := c.state()
	switch {
	case s.next == nil:
		c.mu.Unlock()
		return ErrNoNextCA
	case s.next.key != nil:
		c.mu.Unlock()
		return nil
	case !keyMatches(s.next.cert, key):
		c.mu.Unlock()
		return errors.New("next CA: the key does not match the certificate")
	}
	kp := keyPair{cert: s.next.cert, key: key}
	if err := c.writeNext(kp); err != nil {
		c.mu.Unlock()
		return err
	}
	c.st.Store(newState(s.cur, &kp, false))
	c.mu.Unlock()
	c.changed()
	return nil
}

// writeNext writes kp as the next CA, replacing any files of it.
func (c *CA) writeNext(kp keyPair) error {
	if c.dir == "" {
		return errors.New("next CA: the CA has no data dir")
	}
	der, err := x509.MarshalPKCS8PrivateKey(kp.key)
	if err != nil {
		return fmt.Errorf("encode next CA key: %w", err)
	}
	if err := replaceFile(filepath.Join(c.dir, NextCACertFile), EncodeCertPEM(kp.cert), 0o644); err != nil {
		return err
	}
	return replaceFile(filepath.Join(c.dir, NextCAKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

// Cutover makes the hub serve certificates of the next CA. Setting it again
// is a no-op; it needs the next CA's key.
func (c *CA) Cutover() error {
	c.mu.Lock()
	s := c.state()
	if s.next == nil || s.next.key == nil {
		c.mu.Unlock()
		return ErrNoNextCA
	}
	if s.cutover {
		c.mu.Unlock()
		return nil
	}
	c.st.Store(newState(s.cur, s.next, true))
	c.mu.Unlock()
	c.changed()
	return nil
}

// Finish ends the rotation on this hub: the next CA becomes the only one,
// and its files replace ca.crt and ca.key, which deletes the current key.
// A crash between the two renames is completed by LoadOrCreateCA, and a
// Finish that failed between them is completed by calling it again: a
// rename whose source is gone is done when its target is the next CA's.
func (c *CA) Finish() error {
	c.mu.Lock()
	s := c.state()
	if s.next == nil || s.next.key == nil {
		c.mu.Unlock()
		return ErrNoNextCA
	}
	if c.dir == "" {
		c.mu.Unlock()
		return errors.New("finish CA rotation: the CA has no data dir")
	}
	for _, f := range [][2]string{{NextCACertFile, CACertFile}, {NextCAKeyFile, CAKeyFile}} {
		src, dst := filepath.Join(c.dir, f[0]), filepath.Join(c.dir, f[1])
		err := os.Rename(src, dst)
		if errors.Is(err, os.ErrNotExist) && c.holdsNext(dst, s.next) {
			continue
		}
		if err != nil {
			c.mu.Unlock()
			return fmt.Errorf("finish CA rotation: %w", err)
		}
	}
	syncDir(c.dir)
	c.st.Store(newState(*s.next, nil, false))
	c.mu.Unlock()
	c.changed()
	return nil
}

// holdsNext reports whether path, ca.crt or ca.key, already holds next's
// certificate or key: what a rename of Finish left there.
func (c *CA) holdsNext(path string, next *keyPair) bool {
	if filepath.Base(path) == CACertFile {
		cert, err := LoadCACert(c.dir)
		return err == nil && cert.Equal(next.cert)
	}
	key, err := ReadKey(path)
	return err == nil && keyMatches(next.cert, key)
}

// Abandon ends a rotation this hub missed (it lacks the new CA's key, or a
// node certificate of it): cert, the new CA, becomes the only CA, without a
// key, and every CA key file in the data dir is deleted. ca.crt is replaced
// first, so a crash leaves a certificate and key that do not match, which
// LoadOrCreateCA refuses. The hub can then sign nothing and trust nothing
// of the old CA.
func (c *CA) Abandon(cert *x509.Certificate) error {
	c.mu.Lock()
	if c.dir == "" {
		c.mu.Unlock()
		return errors.New("abandon CA: the CA has no data dir")
	}
	if err := replaceFile(filepath.Join(c.dir, CACertFile), EncodeCertPEM(cert), 0o644); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("abandon CA: %w", err)
	}
	for _, f := range []string{CAKeyFile, NextCAKeyFile, NextCACertFile} {
		if err := os.Remove(filepath.Join(c.dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.mu.Unlock()
			return fmt.Errorf("abandon CA: %w", err)
		}
	}
	syncDir(c.dir)
	c.st.Store(newState(keyPair{cert: cert}, nil, false))
	c.mu.Unlock()
	c.changed()
	return nil
}

// DropNext forgets the next CA and deletes its files: what a rotation that
// was never committed left behind.
func (c *CA) DropNext() error {
	c.mu.Lock()
	s := c.state()
	if s.next == nil {
		c.mu.Unlock()
		return nil
	}
	if c.dir != "" {
		for _, f := range []string{NextCAKeyFile, NextCACertFile} {
			if err := os.Remove(filepath.Join(c.dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
				c.mu.Unlock()
				return fmt.Errorf("drop next CA: %w", err)
			}
		}
	}
	c.st.Store(newState(s.cur, nil, false))
	c.mu.Unlock()
	c.changed()
	return nil
}

// replaceFile writes data to path with mode perm through a temporary file in
// the same directory, so path is either the old or the new content. The
// content reaches the disk before the rename.
func replaceFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("write %s: %w", path, err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir flushes a directory's entries, so renames survive a crash. A
// failure is ignored: not every platform can sync a directory.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
