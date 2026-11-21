// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrFingerprintMismatch means the hub did not present the CA pinned by the token.
var ErrFingerprintMismatch = errors.New("hub CA does not match the token's fingerprint")

// PinnedTLSConfig returns a client TLS config for enrollment: the hub must present
// a chain that includes the CA with fingerprint fp, and its leaf must be valid for
// serverName under that CA. System roots are not consulted.
func PinnedTLSConfig(fp [sha256.Size]byte, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// Standard verification is replaced, not skipped: VerifyConnection below
		// verifies the chain against the pinned CA and checks the hostname.
		InsecureSkipVerify: true, //nolint:gosec // see VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinned(cs.PeerCertificates, fp, serverName)
		},
	}
}

// PinnedAnyTLSConfig is PinnedTLSConfig for a hub that may present a chain
// of any of the CAs cas: during a hub CA rotation, the one it served or the
// one it cut over to.
func PinnedAnyTLSConfig(cas []*x509.Certificate, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// Standard verification is replaced, not skipped: see PinnedTLSConfig.
		InsecureSkipVerify: true, //nolint:gosec // see VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			err := ErrFingerprintMismatch
			for _, ca := range cas {
				if err = verifyPinned(cs.PeerCertificates, Fingerprint(ca), serverName); err == nil {
					return nil
				}
			}
			return err
		},
	}
}

func verifyPinned(chain []*x509.Certificate, fp [sha256.Size]byte, serverName string) error {
	if len(chain) == 0 {
		return errors.New("hub presented no certificate")
	}
	var ca *x509.Certificate
	for _, c := range chain {
		if Fingerprint(c) == fp {
			ca = c
			break
		}
	}
	if ca == nil {
		return ErrFingerprintMismatch
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   serverName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("verify hub certificate: %w", err)
	}
	return nil
}
