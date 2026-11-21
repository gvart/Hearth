// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

const waitFor = 15 * time.Second

// testLogger discards the log, unless HEARTH_TEST_CLUSTER_LOG is set.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	if os.Getenv("HEARTH_TEST_CLUSTER_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil)).With("test", t.Name())
	}
	return slog.New(slog.DiscardHandler)
}

// mintHubCert issues a node certificate for id with ca, as whoever holds
// that CA's key could.
func mintHubCert(t *testing.T, ca *pki.CA, id string) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, id)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.SignHubCSR(csr, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
}

func newTestCA(t *testing.T) *pki.CA {
	t.Helper()
	ca, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// freeAddr returns a loopback address with a port that was free a moment
// ago, for a hub that never listens on it.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func hubCert(t *testing.T, ca *pki.CA, id string) tls.Certificate {
	t.Helper()
	cert, err := loadOrIssueNodeCert(t.TempDir(), ca, id, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func deviceCert(t *testing.T, ca *pki.CA) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "pi")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.SignClientCSR(csr, "pi", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}
