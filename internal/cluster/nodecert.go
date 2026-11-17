// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

// renewBefore is how long before expiry a node renews its own certificate.
const renewBefore = 30 * 24 * time.Hour

var nodeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidNodeID checks a node ID: 1 to 63 of [a-z0-9._-], starting with a
// letter or digit.
func ValidNodeID(id string) error {
	if !nodeIDPattern.MatchString(id) {
		return fmt.Errorf("invalid node ID %q: want 1-63 of [a-z0-9._-], starting with a letter or digit", id)
	}
	return nil
}

// NodeID returns the data dir's persisted node ID. If there is none yet, it
// persists want, or, when want is empty, an ID derived from hostname plus a
// short random suffix. A want that differs from the persisted ID is an error:
// a data dir belongs to one node for life.
func NodeID(dataDir, want, hostname string) (string, error) {
	dir := filepath.Join(dataDir, RaftDir)
	path := filepath.Join(dir, nodeIDFile)
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		id := strings.TrimSpace(string(b))
		if want != "" && want != id {
			return "", fmt.Errorf("--node-id %s: this data dir belongs to node %s", want, id)
		}
		return id, ValidNodeID(id)
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("read node ID: %w", err)
	}
	id := want
	if id == "" {
		if id, err = deriveNodeID(hostname); err != nil {
			return "", err
		}
	}
	if err := ValidNodeID(id); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create raft dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write node ID: %w", err)
	}
	return id, nil
}

func deriveNodeID(hostname string) (string, error) {
	base := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		default:
			return '-'
		}
	}, strings.Split(hostname, ".")[0])
	base = strings.Trim(base, "-")
	if len(base) > 40 {
		base = base[:40]
	}
	if base == "" {
		base = "hub"
	}
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate node ID: %w", err)
	}
	return base + "-" + hex.EncodeToString(b[:]), nil
}

// loadOrIssueNodeCert loads the node certificate from dir, or, when it is
// missing or about to expire, issues a new one with the local CA key (every
// voter holds it) and saves it.
func loadOrIssueNodeCert(dir string, ca *pki.CA, nodeID string, now time.Time) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, nodeCertFile), filepath.Join(dir, nodeKeyFile)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		id, idErr := pki.HubNodeID(cert.Leaf)
		if idErr == nil && id == nodeID && now.Add(renewBefore).Before(cert.Leaf.NotAfter) {
			return cert, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, err
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return tls.Certificate{}, err
		}
	}
	key, err := pki.NewKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	csr, err := pki.NewCSR(key, nodeID)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := ca.SignHubCSR(csr, nodeID, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writeNodeCert(dir, leaf, key); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// writeNodeCert saves a node certificate (0644) and its key (0600).
func writeNodeCert(dir string, cert *x509.Certificate, key crypto.Signer) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create raft dir: %w", err)
	}
	if err := pki.WriteKey(filepath.Join(dir, nodeKeyFile), key); err != nil {
		return err
	}
	return pki.WriteCertFile(filepath.Join(dir, nodeCertFile), cert)
}
