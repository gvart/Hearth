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
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

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
			client := newForwardClient(ca, func() *tls.Certificate { return &own }, epochA)
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

// restoredLeader starts a one-hub cluster the way a restored hub starts it.
func restoredLeader(t *testing.T, ca *pki.CA) *testNode {
	t.Helper()
	dir := t.TempDir()
	if err := WriteNewEpoch(dir); err != nil {
		t.Fatal(err)
	}
	n := startNode(t, ca, "n1", dir, "", true)
	leaderOf(t, n)
	return n
}

// TestRestoredClusterRefusesAHubWithoutEpochs: such a hub would get a server
// certificate without the epoch, and writes would stop once it led the cluster.
func TestRestoredClusterRefusesAHubWithoutEpochs(t *testing.T) {
	ca := newTestCA(t)
	n1 := restoredLeader(t, ca)
	srv := joinServer(t, n1, ca)
	token := joinToken(t, n1, ca, time.Now().Add(time.Hour))
	params := JoinParams{URL: srv.URL, Token: token, DataDir: t.TempDir(), NodeID: "old", RaftAddress: freeAddr(t), noClusterEpochs: true}
	err := Join(t.Context(), params)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("Join = %v, want a failed precondition telling the operator to upgrade", err)
	}
	st, err := n1.Status()
	if err != nil || len(st.Peers) != 1 {
		t.Fatalf("peers = %+v, %v; the refused hub must not be added", st.Peers, err)
	}
	// The refusal did not burn the token: the upgraded hub uses it.
	params.DataDir, params.noClusterEpochs = t.TempDir(), false
	if err := Join(t.Context(), params); err != nil {
		t.Fatalf("Join after the upgrade: %v", err)
	}
}

func TestNeverRestoredClusterAcceptsOlderHubs(t *testing.T) {
	ca := newTestCA(t)
	n1 := startNode(t, ca, "n1", "", "", true)
	leaderOf(t, n1)
	srv := joinServer(t, n1, ca)
	dir := t.TempDir()
	err := Join(t.Context(), JoinParams{
		URL: srv.URL, Token: joinToken(t, n1, ca, time.Now().Add(time.Hour)),
		DataDir: dir, NodeID: "old", RaftAddress: freeAddr(t), noClusterEpochs: true,
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, EpochFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a hub of a never-restored cluster got an epoch file: %v", err)
	}
}

// TestJoinedHubKeepsItsEpochWithoutItsCertificate: a hub that lost node.crt
// issues itself a new one, which must stay in the cluster's epoch.
func TestJoinedHubKeepsItsEpochWithoutItsCertificate(t *testing.T) {
	ca := newTestCA(t)
	n1 := restoredLeader(t, ca)
	srv := joinServer(t, n1, ca)
	n2 := joinAndStart(t, srv.URL, joinToken(t, n1, ca, time.Now().Add(time.Hour)), "n2")
	dir, addr := n2.dir, n2.Addr()
	n2.stop()
	for _, name := range []string{nodeCertFile, nodeKeyFile} {
		if err := os.Remove(filepath.Join(dir, RaftDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	again := startNode(t, ca, "n2", dir, addr, false)
	if again.Epoch() != n1.Epoch() {
		t.Fatalf("epoch after losing node.crt = %q, want the cluster's %q", again.Epoch(), n1.Epoch())
	}
	upsert(t, n1, "after-renewal")
	eventually(t, "n2 to replicate again", func() bool { return hasDevice(again, "after-renewal") })
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
