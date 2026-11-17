// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// File names inside a data dir.
const (
	CACertFile = "ca.crt"
	CAKeyFile  = "ca.key"
)

// Validity periods.
const (
	caValidity         = 10 * 365 * 24 * time.Hour
	serverCertValidity = 365 * 24 * time.Hour
	// ClientCertValidity is how long an enrolled agent's certificate is valid.
	ClientCertValidity = 365 * 24 * time.Hour
	// clockSkew backdates NotBefore so slightly-off device clocks still accept fresh certs.
	clockSkew = 5 * time.Minute
)

// deviceURIPrefix prefixes the device ID in a client certificate's URI SAN.
const deviceURIPrefix = "urn:hearth:device:"

// CA is the hub certificate authority. Its key never leaves the hub data dir.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// LoadOrCreateCA loads the CA from dir, creating an ECDSA P-256 CA on first use.
// The key file is written with mode 0600.
func LoadOrCreateCA(dir string, now time.Time) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		return loadCA(certPath, keyPath)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		return createCA(dir, certPath, keyPath, now)
	case certErr != nil && !errors.Is(certErr, os.ErrNotExist):
		return nil, fmt.Errorf("stat CA cert: %w", certErr)
	case keyErr != nil && !errors.Is(keyErr, os.ErrNotExist):
		return nil, fmt.Errorf("stat CA key: %w", keyErr)
	default:
		return nil, fmt.Errorf("CA in %s is incomplete: need both %s and %s", dir, CACertFile, CAKeyFile)
	}
}

// LoadCACert reads only the CA certificate from dir.
func LoadCACert(dir string) (*x509.Certificate, error) {
	b, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	return ParseCertPEM(b)
}

func createCA(dir, certPath, keyPath string, now time.Time) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Hearth CA"},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	if err := WriteKey(keyPath, key); err != nil {
		return nil, err
	}
	if err := writeFile(certPath, EncodeCertPEM(cert), 0o644); err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key}, nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ReadKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key}, nil
}

// Cert returns the CA certificate.
func (c *CA) Cert() *x509.Certificate { return c.cert }

// Fingerprint returns the SHA-256 of the CA certificate's DER encoding.
func (c *CA) Fingerprint() [sha256.Size]byte { return Fingerprint(c.cert) }

// Fingerprint returns the SHA-256 of cert's DER encoding.
func Fingerprint(cert *x509.Certificate) [sha256.Size]byte { return sha256.Sum256(cert.Raw) }

// IssueServerCert issues a fresh hub TLS certificate for hosts (DNS names or IPs).
// The returned chain includes the CA so pinning clients can verify it.
func (c *CA) IssueServerCert(hosts []string, now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Hearth hub"},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(serverCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create server cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse server cert: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// SignClientCSR verifies the CSR's self-signature and issues a client certificate
// binding its public key to deviceID. The CSR's subject is ignored: identity is
// assigned by the hub, never chosen by the device.
func (c *CA) SignClientCSR(csrDER []byte, deviceID string, now time.Time) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("check CSR signature: %w", err)
	}
	uri, err := url.Parse(deviceURIPrefix + deviceID)
	if err != nil {
		return nil, fmt.Errorf("device URI: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID},
		URIs:         []*url.URL{uri},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ClientCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign client cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse client cert: %w", err)
	}
	return cert, nil
}

// DeviceID extracts the device ID from a client certificate's URI SAN.
func DeviceID(cert *x509.Certificate) (string, error) {
	for _, u := range cert.URIs {
		if id, ok := strings.CutPrefix(u.String(), deviceURIPrefix); ok && id != "" {
			return id, nil
		}
	}
	return "", errors.New("certificate carries no device ID")
}

// SerialString is the canonical text form of a certificate serial, as stored in the hub.
func SerialString(cert *x509.Certificate) string { return cert.SerialNumber.Text(16) }

// NewDeviceID returns a random device ID.
func NewDeviceID() (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate device ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// NewKey returns a fresh ECDSA P-256 key.
func NewKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return k, nil
}

// NewCSR returns a DER-encoded certificate request signed by key.
func NewCSR(key crypto.Signer, commonName string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return der, nil
}

// EncodeCertPEM PEM-encodes cert.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// ParseCertPEM parses the first certificate in a PEM block.
func ParseCertPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("parse certificate: no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// WriteKey writes key as PKCS#8 PEM with mode 0600, refusing to overwrite.
func WriteKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode key: %w", err)
	}
	return writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

// ReadKey reads a PKCS#8 PEM private key.
func ReadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("read key %s: no PRIVATE KEY PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", path, err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("parse key %s: unsupported key type %T", path, k)
	}
	return s, nil
}

// writeFile creates path with mode perm, failing if it already exists.
func writeFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// WriteCertFile writes cert as PEM with mode 0644, refusing to overwrite.
func WriteCertFile(path string, cert *x509.Certificate) error {
	return writeFile(path, EncodeCertPEM(cert), 0o644)
}

func newSerial() (*big.Int, error) {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return s, nil
}
