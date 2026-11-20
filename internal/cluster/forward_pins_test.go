// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/store"
)

// certSwapServer serves h's ClusterService with the hub listener's server
// certificate, and, to a client asking for nodeCertSNI, with whatever node
// certificate the test stores in node: the leader's own, or one an attacker
// holding the old CA key minted. nil serves the server certificate to every
// client, as a hub that does not know nodeCertSNI would.
type certSwapServer struct {
	url  string
	node atomic.Pointer[tls.Certificate]
	mu   sync.Mutex
	snis []string
}

func serveCertSwap(t *testing.T, h *rotHub) *certSwapServer {
	t.Helper()
	s := &certSwapServer{}
	base := hub.TLSConfigFunc(h.ca, h.srvCert.Load)
	mux := http.NewServeMux()
	mux.Handle(NewJoinServer(h.Node, h.st, h.ca, policy.New(h.st.Audit()), slog.New(slog.DiscardHandler)).Handler())
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = base.Clone()
	srv.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		s.snis = append(s.snis, hello.ServerName)
		s.mu.Unlock()
		c, err := base.GetConfigForClient(hello)
		if err != nil {
			return nil, err
		}
		if node := s.node.Load(); node != nil && hello.ServerName == nodeCertSNI {
			c.Certificates = []tls.Certificate{*node}
		}
		return c, nil
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshakes
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *certSwapServer) askedForNodeCert() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.snis {
		if n == nodeCertSNI {
			return true
		}
	}
	return false
}

// TestForwardClientPinsInRotation covers the calls a hub makes to another
// hub's ClusterService during a hub CA rotation: the other hub must present
// its pinned node certificate or one of the new CA. A certificate minted
// with the old CA key for the right hub fails each of Forward, CAInfo and
// FetchCAKey. Outside a rotation nothing changes.
func TestForwardClientPinsInRotation(t *testing.T) {
	ctx := t.Context()
	hubs, thief := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	var follower *rotHub
	for _, h := range hubs {
		if h != leader {
			follower = h
			break
		}
	}
	swap := serveCertSwap(t, leader)
	if err := leader.st.Hubs().SetAgentURL(ctx, leader.ID(), swap.url); err != nil {
		t.Fatal(err)
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to call the leader at its new URL", func() bool {
			return h.hubURLs(ctx)[leader.ID()] == swap.url
		})
	}

	forward := func() error {
		now := time.Now().Unix()
		_, _, _, err := follower.forward(ctx, leader.ID(), leader.Addr(), store.UpsertDevice{ID: "d", Name: "d", FirstSeen: now, LastSeen: now})
		return err
	}
	caInfo := func() error {
		_, err := follower.hubCAInfo(ctx, leader.ID(), leader.Addr())
		return err
	}
	fetchKey := func(newFP string) func() error {
		return func() error {
			c, err := follower.memberClient(ctx, leader.ID(), leader.Addr())
			if err != nil {
				return err
			}
			key, err := pki.NewKey()
			if err != nil {
				t.Fatal(err)
			}
			csr, err := pki.NewCSR(key, follower.ID())
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.FetchCAKey(ctx, connect.NewRequest(&clusterv1.FetchCAKeyRequest{NewCaFingerprint: newFP, Csr: csr}))
			return err
		}
	}

	// No rotation: the listener's server certificate, for its host name,
	// as before; nobody asks for a node certificate.
	swap.node.Store(new(mintHubCert(t, thief, leader.ID())))
	for name, call := range map[string]func() error{"Forward": forward, "CAInfo": caInfo} {
		if err := call(); err != nil {
			t.Errorf("%s with no rotation: %v", name, err)
		}
	}
	if swap.askedForNodeCert() {
		t.Error("a hub asked for a node certificate with no rotation under way")
	}

	// The window: every hub holds the new key and a node certificate of it,
	// and none cut over.
	for _, h := range hubs {
		h.RecordNodeCert(ctx)
	}
	for _, h := range hubs {
		eventually(t, "every hub's certificate recorded on "+h.ID(), func() bool {
			for _, o := range hubs {
				certs, err := h.st.Hubs().Certs(ctx, o.ID())
				if err != nil || len(certs) != 1 || certs[0].Fingerprint == "" {
					return false
				}
			}
			return true
		})
	}
	pinned := *leader.stream.currentCert()
	swap.node.Store(&pinned)
	plan, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to hold the new key and a node certificate of it", func() bool {
			i := h.localCAInfo()
			return i.NextFP == plan.NewCAFP && i.HasNextKey && i.HasNextCert && !i.CutOver
		})
	}
	ofNewCA := mintHubCert(t, leader.ca, leader.ID())
	if pki.FingerprintHex(leader.ca.IssuerOf(ofNewCA.Leaf)) != plan.NewCAFP {
		t.Fatal("the leader's CA does not sign with the new CA")
	}

	calls := map[string]func() error{"Forward": forward, "CAInfo": caInfo, "FetchCAKey": fetchKey(plan.NewCAFP)}
	for _, tc := range []struct {
		name string
		node *tls.Certificate
		// refused is part of the error a refused certificate gets; empty
		// when it is accepted.
		refused string
	}{
		{"the pinned node certificate", &pinned, ""},
		{"a node certificate of the new CA", &ofNewCA, ""},
		{"an old-CA node certificate other than the pinned one", new(mintHubCert(t, thief, leader.ID())), errNotPinned.Error()},
		{"the old-CA server certificate", nil, "peer is not a hub"},
	} {
		for name, call := range calls {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				swap.node.Store(tc.node)
				// A new handshake for each case, not a pooled connection.
				follower.pinHTTP.CloseIdleConnections()
				err := call()
				if tc.refused == "" && err != nil {
					t.Errorf("%s = %v, want it accepted", name, err)
				}
				if tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)) {
					t.Errorf("%s = %v, want the server certificate refused with %q", name, err, tc.refused)
				}
			})
		}
	}
	follower.pinHTTP.CloseIdleConnections()
}

// TestServeNodeCert covers the hub listener's side: a client asking for
// nodeCertSNI gets the hub's node certificate, every other client the
// listener's own certificate, with the listener's settings either way.
func TestServeNodeCert(t *testing.T) {
	ca := newTestCA(t)
	n := startNode(t, ca, "n1", "", "", true)
	srvCert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg := n.ServeNodeCert(hub.TLSConfigFunc(ca, func() *tls.Certificate { return &srvCert }))
	for _, tc := range []struct {
		sni      string
		wantNode bool
	}{
		{nodeCertSNI, true},
		{"", false},
		{"hub.example", false},
	} {
		c, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: tc.sni})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Certificates) != 1 {
			t.Fatalf("SNI %q: %d certificates, want 1", tc.sni, len(c.Certificates))
		}
		got := c.Certificates[0].Certificate[0]
		isNode := string(got) == string(n.stream.currentCert().Certificate[0])
		if isNode != tc.wantNode {
			t.Errorf("SNI %q: serves the node certificate = %v, want %v", tc.sni, isNode, tc.wantNode)
		}
		if c.ClientAuth != tls.VerifyClientCertIfGiven || c.ClientCAs == nil || c.VerifyConnection == nil {
			t.Errorf("SNI %q: the listener's client authentication is lost", tc.sni)
		}
	}
}

// TestClusterHTTPFailsClosed: a hub that cannot read whether a rotation is
// under way makes no ClusterService call rather than one without pins.
func TestClusterHTTPFailsClosed(t *testing.T) {
	ca := newTestCA(t)
	n := startNode(t, ca, "n1", "", "", true)
	leaderOf(t, n)
	if hc, err := n.clusterHTTP(t.Context()); err != nil || hc != n.fwdHTTP {
		t.Fatalf("clusterHTTP with no rotation = %p, %v; want fwdHTTP", hc, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if hc, err := n.clusterHTTP(ctx); err == nil {
		t.Fatalf("clusterHTTP with an unreadable store = %p, want an error", hc)
	}
}
