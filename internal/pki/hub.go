// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// hubURIPrefix prefixes the node ID in a hub node certificate's URI SAN. Device
// certificates carry deviceURIPrefix instead, so a device can never pass as a
// hub on the cluster transport.
const hubURIPrefix = "urn:hearth:hub:"

// HubCertValidity is how long a hub node certificate is valid. A voter holds
// the CA key and renews its own certificate before it expires.
const HubCertValidity = 365 * 24 * time.Hour

// SignHubCSR verifies the CSR's self-signature and issues a hub node
// certificate binding its public key to nodeID. The certificate is valid for
// both ends of a TLS connection, since cluster peers dial each other.
func (c *CA) SignHubCSR(csrDER []byte, nodeID string, now time.Time) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("check CSR signature: %w", err)
	}
	uri, err := url.Parse(hubURIPrefix + nodeID)
	if err != nil {
		return nil, fmt.Errorf("hub URI: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Hearth hub " + nodeID},
		URIs:         []*url.URL{uri},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(HubCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign hub cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse hub cert: %w", err)
	}
	return cert, nil
}

// HubNodeID extracts the node ID from a hub node certificate's URI SAN.
func HubNodeID(cert *x509.Certificate) (string, error) {
	for _, u := range cert.URIs {
		if id, ok := strings.CutPrefix(u.String(), hubURIPrefix); ok && id != "" {
			return id, nil
		}
	}
	return "", errors.New("certificate carries no hub node ID")
}

// KeyDER returns the CA private key as PKCS#8 DER. It exists only to hand the
// key to a joining hub over the pinned join channel: never log or persist the
// result anywhere but a voter's data dir.
func (c *CA) KeyDER() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return nil, fmt.Errorf("encode CA key: %w", err)
	}
	return der, nil
}

// InstallCA writes a CA received from a cluster peer into dir: ca.crt (0644)
// and ca.key (0600), refusing to overwrite either. The certificate must have
// fingerprint want and the key must belong to it.
func InstallCA(dir string, certDER, keyDER []byte, want [sha256.Size]byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("install CA: parse cert: %w", err)
	}
	if Fingerprint(cert) != want {
		return fmt.Errorf("install CA: %w", ErrFingerprintMismatch)
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return errors.New("install CA: malformed key") // never echo key material
	}
	key, ok := k.(crypto.Signer)
	if !ok {
		return fmt.Errorf("install CA: unsupported key type %T", k)
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	if !bytes.Equal(pub, cert.RawSubjectPublicKeyInfo) {
		return errors.New("install CA: key does not match the certificate")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	if err := writeFile(filepath.Join(dir, CAKeyFile),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	if err := WriteCertFile(filepath.Join(dir, CACertFile), cert); err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	return nil
}
