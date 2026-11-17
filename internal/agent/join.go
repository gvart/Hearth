// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
)

// Identity files in the agent data dir.
const (
	CertFile = "agent.crt"
	KeyFile  = "agent.key"
	CAFile   = "ca.crt"
)

// ErrAlreadyEnrolled is returned by Join when the data dir already holds an identity.
var ErrAlreadyEnrolled = errors.New("agent is already enrolled")

// Join enrolls this device with the hub at hubURL using a token string, and
// writes the resulting key (0600), certificate, hub CA and hub URL into dataDir. The hub
// is pinned by the CA fingerprint in the token before the secret is sent.
// It returns the device ID assigned by the hub.
func Join(ctx context.Context, hubURL, token, dataDir, hostname string) (string, error) {
	tok, err := pki.ParseToken(token)
	if err != nil {
		return "", err
	}
	u, err := parseHubURL(hubURL)
	if err != nil {
		return "", err
	}
	certPath := filepath.Join(dataDir, CertFile)
	if _, err := os.Stat(certPath); err == nil {
		return "", fmt.Errorf("%w: %s exists", ErrAlreadyEnrolled, certPath)
	}

	key, err := pki.NewKey()
	if err != nil {
		return "", err
	}
	csr, err := pki.NewCSR(key, hostname)
	if err != nil {
		return "", err
	}

	transport := &http.Transport{TLSClientConfig: pki.PinnedTLSConfig(tok.CAFingerprint, u.Hostname())}
	defer transport.CloseIdleConnections()
	client := agentv1connect.NewEnrollServiceClient(&http.Client{Transport: transport}, u.String())
	resp, err := client.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		TokenSecret: tok.Secret,
		Csr:         csr,
		Hostname:    hostname,
	}))
	if err != nil {
		return "", fmt.Errorf("enroll with %s: %w", u.Host, err)
	}

	ca, cert, err := checkResponse(resp.Msg, tok.CAFingerprint, key.Public())
	if err != nil {
		return "", fmt.Errorf("enroll with %s: %w", u.Host, err)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", fmt.Errorf("create data dir: %w", err)
	}
	// The certificate is written last: its presence marks the agent as enrolled,
	// so leftovers from an interrupted join are safe to replace.
	for _, f := range []string{KeyFile, CAFile, HubURLFile} {
		if err := os.Remove(filepath.Join(dataDir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("remove stale %s: %w", f, err)
		}
	}
	if err := pki.WriteKey(filepath.Join(dataDir, KeyFile), key); err != nil {
		return "", err
	}
	if err := pki.WriteCertFile(filepath.Join(dataDir, CAFile), ca); err != nil {
		return "", err
	}
	if err := writeHubURL(dataDir, u); err != nil {
		return "", err
	}
	if err := pki.WriteCertFile(certPath, cert); err != nil {
		return "", err
	}
	return resp.Msg.GetDeviceId(), nil
}

// checkResponse makes sure the hub returned the pinned CA and a client
// certificate for our key, issued by that CA, for the device ID it claims.
func checkResponse(msg *agentv1.EnrollResponse, fp [32]byte, pub crypto.PublicKey) (ca, cert *x509.Certificate, err error) {
	ca, err = x509.ParseCertificate(msg.GetCaCertificate())
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if pki.Fingerprint(ca) != fp {
		return nil, nil, pki.ErrFingerprintMismatch
	}
	cert, err = x509.ParseCertificate(msg.GetCertificate())
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, nil, fmt.Errorf("verify certificate: %w", err)
	}
	if k, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !k.Equal(pub) {
		return nil, nil, errors.New("certificate is not for our key")
	}
	if id, err := pki.DeviceID(cert); err != nil || id != msg.GetDeviceId() {
		return nil, nil, errors.New("certificate device ID does not match the response")
	}
	return ca, cert, nil
}
