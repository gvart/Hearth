// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

const (
	epochA = "00112233445566778899aabbccddeeff"
	epochB = "ffeeddccbbaa99887766554433221100"
)

func TestRequireEpoch(t *testing.T) {
	ca := newTestCA(t)
	serverCert := func(epoch string) *x509.Certificate {
		c, err := ca.IssueHubServerCert([]string{"127.0.0.1"}, epoch, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf
	}
	tests := []struct {
		name, mine string
		peer       []*x509.Certificate
		ok         bool
	}{
		{"never restored", "", []*x509.Certificate{serverCert("")}, true},
		{"same epoch", epochA, []*x509.Certificate{serverCert(epochA)}, true},
		{"old hub calls a restored one", "", []*x509.Certificate{serverCert(epochA)}, false},
		{"restored hub calls an old one", epochA, []*x509.Certificate{serverCert("")}, false},
		{"two restores", epochA, []*x509.Certificate{serverCert(epochB)}, false},
		{"no certificate", epochA, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireEpoch(tt.mine)(tls.ConnectionState{PeerCertificates: tt.peer})
			if tt.ok && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tt.ok && !errors.Is(err, store.ErrCertRevoked) {
				t.Errorf("err = %v, want a refusal matching ErrCertRevoked", err)
			}
		})
	}
}

func TestCheckPeerCertRefusesAnotherEpoch(t *testing.T) {
	ca := newTestCA(t)
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	peer := func(epoch string) *x509.Certificate {
		c, err := loadOrIssueNodeCert(t.TempDir(), ca, "peer", epoch, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf
	}
	n := &Node{store: st, epoch: epochA}
	if err := n.checkPeerCert(peer(epochA)); err != nil {
		t.Errorf("a hub of this epoch was refused: %v", err)
	}
	for _, other := range []string{"", epochB} {
		// refuseRevoked accepts on a read error, so the refusal must be this one.
		if err := n.refuseRevoked(peer(other)); !errors.Is(err, store.ErrCertRevoked) {
			t.Errorf("epoch %q: refuseRevoked = %v, want a refusal", other, err)
		}
	}
}

// TestRenewedNodeCertKeepsItsEpoch: a joined hub has no epoch file, only its
// certificate, and must not fall out of the cluster when it renews it.
func TestRenewedNodeCertKeepsItsEpoch(t *testing.T) {
	ca, dir := newTestCA(t), t.TempDir()
	now := time.Now()
	first, err := loadOrIssueNodeCert(dir, ca, "n1", epochA, now)
	if err != nil {
		t.Fatal(err)
	}
	later := first.Leaf.NotAfter.Add(-renewBefore + time.Hour)
	renewed, err := loadOrIssueNodeCert(dir, ca, "n1", "", later)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("the certificate was not renewed")
	}
	if got := pki.HubEpoch(renewed.Leaf); got != epochA {
		t.Errorf("renewed epoch = %q, want %q", got, epochA)
	}
}

// TestForwardClientRefusesAnotherEpoch: the outbound hub-to-hub client does not
// talk to a hub of another epoch, though its certificate comes from the same CA.
func TestForwardClientRefusesAnotherEpoch(t *testing.T) {
	ca := newTestCA(t)
	own, err := loadOrIssueNodeCert(t.TempDir(), ca, "n1", epochA, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, epoch string
		ok          bool
	}{
		{"same epoch", epochA, true},
		{"old cluster", "", false},
		{"another restore", epochB, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ca.IssueHubServerCert([]string{"127.0.0.1"}, tt.epoch, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
			srv.StartTLS()
			defer srv.Close()
			client := newForwardClient(ca, own, epochA)
			defer client.CloseIdleConnections()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
			if tt.ok && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tt.ok && !errors.Is(err, store.ErrCertRevoked) {
				t.Errorf("err = %v, want a refusal of the other epoch", err)
			}
		})
	}
}

func TestReadEpoch(t *testing.T) {
	dir := t.TempDir()
	if got, err := readEpoch(dir); err != nil || got != "" {
		t.Errorf("no file: %q, %v", got, err)
	}
	if err := WriteNewEpoch(dir); err != nil {
		t.Fatal(err)
	}
	got, err := readEpoch(dir)
	if err != nil || len(got) != 2*epochBytes {
		t.Errorf("written epoch: %q, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, EpochFile), []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEpoch(dir); err == nil {
		t.Error("a malformed epoch file was accepted")
	}
}
