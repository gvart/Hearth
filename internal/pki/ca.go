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
	"sync"
	"sync/atomic"
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

// CA is the hub certificate authority. Its key never leaves a hub voter's data
// dir; it is replicated only over the pinned join channel (see KeyDER).
//
// While the CA is rotated (see rotate.go) it holds two key pairs: the current
// one (ca.crt, ca.key) and the next (ca.next.crt, ca.next.key). Both are
// trusted; new certificates are signed by the next CA as soon as its key is
// here, and the hub's TLS server certificates by the current CA until the
// cutover. A CA is safe for concurrent use.
type CA struct {
	// dir is the data dir the CA files live in; empty for a CA that was
	// not loaded from one (rotation then fails).
	dir string
	st  atomic.Pointer[caState]
	// mu serializes changes of st and of the files.
	mu sync.Mutex
	// onChange are called after every change of st, outside mu.
	onChangeMu sync.Mutex
	onChange   []func()
}

// keyPair is a CA certificate and its key; key is nil for a next CA whose
// key this hub has not fetched yet.
type keyPair struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// caState is the CA's state at one moment; it is never modified once stored.
type caState struct {
	cur  keyPair
	next *keyPair
	// active: a rotation to next is under way, as the replicated store
	// shows. Until then next is neither trusted nor signs: a next CA whose
	// rotation never started is known to no other hub.
	active  bool
	cutover bool
	pool    *x509.CertPool
}

func newState(cur keyPair, next *keyPair, active, cutover bool) *caState {
	active = active && next != nil
	pool := x509.NewCertPool()
	pool.AddCert(cur.cert)
	if active {
		pool.AddCert(next.cert)
	}
	// A hub without the CA key (a storage-only member) cuts over without
	// the next key; one holding the current key needs the next one.
	cutover = cutover && active && (next.key != nil || cur.key == nil)
	return &caState{cur: cur, next: next, active: active, cutover: cutover, pool: pool}
}

// serving is the key pair that signs the hub's TLS server certificates and
// that clients pin: the next CA after the cutover, the current one before.
func (s *caState) serving() keyPair {
	if s.cutover {
		return *s.next
	}
	return s.cur
}

// signer is the key pair that signs new client and hub node certificates:
// the next CA as soon as this hub holds its key and the rotation to it is
// under way.
func (s *caState) signer() keyPair {
	if s.active && s.next.key != nil {
		return *s.next
	}
	return s.cur
}

func caFrom(dir string, cur keyPair, next *keyPair) *CA {
	c := &CA{dir: dir}
	c.st.Store(newState(cur, next, false, false))
	return c
}

func (c *CA) state() *caState { return c.st.Load() }

// LoadOrCreateCA loads the CA from dir, creating an ECDSA P-256 CA on first use.
// The key file is written with mode 0600. A next CA left by a rotation is
// loaded too, and a rotation's finish interrupted between its two renames is
// completed.
func LoadOrCreateCA(dir string, now time.Time) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	if err := recoverFinish(dir); err != nil {
		return nil, err
	}
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		cur, err := loadKeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		next, err := loadNext(dir)
		if err != nil {
			return nil, err
		}
		return caFrom(dir, cur, next), nil
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
	kp, err := generateKeyPair(now)
	if err != nil {
		return nil, err
	}
	if err := WriteKey(keyPath, kp.key); err != nil {
		return nil, err
	}
	if err := writeFile(certPath, EncodeCertPEM(kp.cert), 0o644); err != nil {
		return nil, err
	}
	return caFrom(dir, kp, nil), nil
}

// generateKeyPair creates a new self-signed CA in memory.
func generateKeyPair(now time.Time) (keyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return keyPair{}, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return keyPair{}, err
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
		return keyPair{}, fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return keyPair{}, fmt.Errorf("parse CA cert: %w", err)
	}
	return keyPair{cert: cert, key: key}, nil
}

func loadKeyPair(certPath, keyPath string) (keyPair, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return keyPair{}, fmt.Errorf("read CA cert: %w", err)
	}
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return keyPair{}, err
	}
	key, err := ReadKey(keyPath)
	if err != nil {
		return keyPair{}, err
	}
	// A key copied in by hand, as after a restore without it, must be this
	// CA's.
	if !keyMatches(cert, key) {
		return keyPair{}, fmt.Errorf("CA key %s does not match the CA certificate %s: copy the ca.key of this hub's CA", keyPath, certPath)
	}
	return keyPair{cert: cert, key: key}, nil
}

func keyMatches(cert *x509.Certificate, key crypto.Signer) bool {
	pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(key.Public())
}

// Cert returns the CA certificate clients pin and the hub serves at /ca.crt:
// the current CA, or the next one after a rotation's cutover.
func (c *CA) Cert() *x509.Certificate { return c.state().serving().cert }

// Fingerprint returns the SHA-256 of Cert's DER encoding.
func (c *CA) Fingerprint() [sha256.Size]byte { return Fingerprint(c.Cert()) }

// Fingerprint returns the SHA-256 of cert's DER encoding.
func Fingerprint(cert *x509.Certificate) [sha256.Size]byte { return sha256.Sum256(cert.Raw) }

// FingerprintHex is Fingerprint as lowercase hex, the form the hub stores.
func FingerprintHex(cert *x509.Certificate) string {
	fp := Fingerprint(cert)
	return hex.EncodeToString(fp[:])
}

// IssueServerCert issues a fresh hub TLS certificate for hosts (DNS names or IPs).
// The returned chain includes the CA so pinning clients can verify it.
func (c *CA) IssueServerCert(hosts []string, now time.Time) (tls.Certificate, error) {
	return c.IssueHubServerCert(hosts, "", now)
}

// IssueHubServerCert is IssueServerCert for a hub of cluster epoch epoch, which
// other hubs check before they call it.
func (c *CA) IssueHubServerCert(hosts []string, epoch string, now time.Time) (tls.Certificate, error) {
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
	if epoch != "" {
		u, err := url.Parse(hubEpochURIPrefix + epoch)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("hub epoch URI: %w", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	ca := c.state().serving()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create server cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse server cert: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
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
	return c.SignClientKey(csr.PublicKey, deviceID, now)
}

// SignClientKey issues a client certificate binding pub to deviceID. A CA
// rotation renews an agent's certificate this way, for the key the agent
// proved it holds by presenting its current certificate.
func (c *CA) SignClientKey(pub crypto.PublicKey, deviceID string, now time.Time) (*x509.Certificate, error) {
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
	ca := c.state().signer()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
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
