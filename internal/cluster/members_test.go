// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// revokedSet is a peerCheck backed by a set of revoked serials.
type revokedSet struct {
	mu      sync.Mutex
	serials map[string]bool
}

func (r *revokedSet) revoke(c tls.Certificate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.serials[pki.SerialString(c.Leaf)] = true
}

func (r *revokedSet) check(c *x509.Certificate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.serials[pki.SerialString(c)] {
		return store.ErrCertRevoked
	}
	return nil
}

// TestTransportRefusesRevokedHubs checks that the raft stream layer refuses a
// revoked hub certificate in both directions, and closes connections that
// were open before the revocation.
func TestTransportRefusesRevokedHubs(t *testing.T) {
	ca := newTestCA(t)
	revoked := &revokedSet{serials: map[string]bool{}}
	server, good, bad := hubCert(t, ca, "server"), hubCert(t, ca, "good"), hubCert(t, ca, "bad")
	ln, err := listenTLS(t.Context(), "127.0.0.1:0", "", server, ca, revoked.check)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	// roundTrip completes the handshake (TLS 1.3 reports a refused client
	// certificate on the first read) and echoes one byte.
	roundTrip := func(c net.Conn) error {
		if _, err := c.Write([]byte("x")); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, 1))
		return err
	}
	dial := func(cert tls.Certificate, check peerCheck) (net.Conn, error) {
		d := &tls.Dialer{Config: clientTLS(cert, ca, check)}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}

	open, err := dial(bad, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = open.Close() })
	if err := roundTrip(open); err != nil {
		t.Fatalf("before revocation: %v", err)
	}

	revoked.revoke(bad)
	c, err := dial(bad, nil)
	if err == nil {
		err = roundTrip(c)
		_ = c.Close()
	}
	if err == nil {
		t.Error("listener accepted a revoked hub certificate")
	}
	c, err = dial(good, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(c); err != nil {
		t.Errorf("listener refused a valid hub certificate: %v", err)
	}
	_ = c.Close()

	// The connection opened before the revocation is closed by the sweep.
	if n := ln.closeRevoked(func(c *x509.Certificate) bool { return revoked.check(c) != nil }); n != 1 {
		t.Errorf("closeRevoked closed %d connections, want 1", n)
	}
	_ = open.SetDeadline(time.Now().Add(5 * time.Second))
	if err := roundTrip(open); err == nil {
		t.Error("connection of a revoked hub still open after the sweep")
	}

	// A dialer refuses a listener whose certificate is revoked.
	revoked.revoke(server)
	dialer, err := listenTLS(t.Context(), "127.0.0.1:0", "", good, ca, revoked.check)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	if c, err := dialer.Dial(raft.ServerAddress(ln.Addr().String()), 5*time.Second); err == nil {
		_ = c.Close()
		t.Error("dialer trusted a listener with a revoked certificate")
	}
}

// nodeCert loads the hub node certificate a node uses.
func nodeCert(t *testing.T, n *testNode) tls.Certificate {
	t.Helper()
	dir := filepath.Join(n.dir, RaftDir)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, nodeCertFile), filepath.Join(dir, nodeKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// recordCerts records the node certificate of every node through leader, as
// RecordNodeCert does on a running hub.
func recordCerts(t *testing.T, leader *testNode, nodes ...*testNode) {
	t.Helper()
	for _, n := range nodes {
		if err := leader.st.Hubs().RecordCert(t.Context(), pki.SerialString(n.cert), n.ID()); err != nil {
			t.Fatalf("record cert of %s: %v", n.ID(), err)
		}
	}
}

// openConnsOf counts n's open raft connections whose peer presents serial.
func openConnsOf(n *testNode, serial string) int {
	n.stream.mu.Lock()
	conns := make([]*trackedConn, 0, len(n.stream.conns))
	for c := range n.stream.conns {
		conns = append(conns, c)
	}
	n.stream.mu.Unlock()
	k := 0
	for _, c := range conns {
		if p := c.peer.Load(); p != nil && pki.SerialString(p) == serial {
			k++
		}
	}
	return k
}

func voters(t *testing.T, n *testNode) []string {
	t.Helper()
	st, err := n.Status()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range st.Peers {
		if p.Suffrage == raft.Voter.String() {
			out = append(out, p.ID)
		}
	}
	return out
}

// TestRemovedHubRefusedOnRaftPort removes a live follower: its certificate
// is revoked everywhere, its open raft connections are closed within the
// sweep, a new handshake with it fails, and the cluster keeps working.
func TestRemovedHubRefusedOnRaftPort(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t))
	leader := leaderOf(t, nodes...)
	recordCerts(t, leader, nodes...)
	var gone, stays *testNode
	for _, n := range nodes {
		switch {
		case n == leader:
		case gone == nil:
			gone = n
		default:
			stays = n
		}
	}
	serial := pki.SerialString(gone.cert)
	eventually(t, "open raft connections with "+gone.ID(), func() bool { return openConnsOf(leader, serial) > 0 })

	k, err := leader.RemoveMember(t.Context(), gone.ID())
	if err != nil || k != 1 {
		t.Fatalf("RemoveMember(%s) = %d, %v; want 1 revoked", gone.ID(), k, err)
	}
	if got := voters(t, leader); len(got) != 2 {
		t.Fatalf("voters after removal = %v", got)
	}
	for _, n := range []*testNode{leader, stays} {
		eventually(t, "revocation on "+n.ID(), func() bool {
			return errors.Is(n.st.Hubs().CheckCert(t.Context(), serial), store.ErrCertRevoked)
		})
		eventually(t, gone.ID()+"'s raft connections to "+n.ID()+" closed", func() bool { return openConnsOf(n, serial) == 0 })
	}

	// A fresh handshake with the removed hub's certificate fails.
	stream, err := listenTLS(t.Context(), "127.0.0.1:0", "", nodeCert(t, gone), leader.cfg.CA, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	for _, n := range []*testNode{leader, stays} {
		c, err := stream.Dial(raft.ServerAddress(n.Addr()), 5*time.Second)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, err = c.Read(make([]byte, 1))
			_ = c.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Errorf("%s accepted the removed hub's certificate on its raft port: err = %v", n.ID(), err)
		}
	}

	// The removed hub, still running, cannot disturb the other two.
	for i := range 3 {
		upsert(t, leaderOf(t, leader, stays), "after-removal-"+string(rune('a'+i)))
		time.Sleep(300 * time.Millisecond)
	}
	if hasDevice(gone, "after-removal-a") {
		t.Error("the removed hub still receives writes")
	}
}

// TestRemoveFreesQuorum is the reason for removal: a 3-voter cluster with a
// dead hub tolerates no further failure until the dead hub is removed and
// replaced. The removal goes through a follower, forwarded to the leader.
func TestRemoveFreesQuorum(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	for _, h := range hubs {
		ctx, cancel := context.WithTimeout(t.Context(), waitFor)
		h.RecordNodeCert(ctx)
		cancel()
	}
	fs := followers(hubs, leader)
	dead, other := fs[0], fs[1]
	deadSerial := pki.SerialString(dead.cert)
	dead.kill()
	eventually(t, "the leader to see "+dead.ID()+" fail", func() bool {
		return leader.members.isFailing(raft.ServerID(dead.ID()))
	})

	// Removing the live follower now would leave the leader with a dead
	// voter: no majority, so it is refused.
	if _, err := leader.RemoveMember(t.Context(), other.ID()); !errors.Is(err, ErrQuorumAtRisk) {
		t.Fatalf("remove a live voter next to a dead one: err = %v, want ErrQuorumAtRisk", err)
	}

	// Through the follower's control socket, forwarded to the leader.
	cc := serveControl(t, other.testNode)
	k, err := cc.RemoveMember(t.Context(), dead.ID())
	if err != nil || k != 1 {
		t.Fatalf("remove %s through %s: %d, %v; want 1 revoked", dead.ID(), other.ID(), k, err)
	}
	if got := voters(t, leader.testNode); len(got) != 2 {
		t.Fatalf("voters after removal = %v", got)
	}
	eventually(t, "the revocation on "+other.ID(), func() bool {
		return errors.Is(other.st.Hubs().CheckCert(t.Context(), deadSerial), store.ErrCertRevoked)
	})
	// Removing it again: it is gone and its certificates are revoked.
	if _, err := cc.RemoveMember(t.Context(), dead.ID()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("remove %s again: err = %v, want ErrNotFound", dead.ID(), err)
	}

	// A replacement joins: three voters again.
	n4 := startNodeBound(t, leader.ca, "n4", "", "", false, (*Node).BindForwarding)
	addVoter(t, leader.testNode, n4)
	if got := voters(t, leader.testNode); len(got) != 3 {
		t.Fatalf("voters with the replacement = %v", got)
	}
	eventually(t, "n4 to catch up", func() bool { return n4.raft.AppliedIndex() >= leader.raft.AppliedIndex() })

	// And the cluster survives another failure.
	other.kill()
	l := leaderOf(t, leader.testNode, n4)
	upsert(t, l, "after-second-failure")
	eventually(t, "the write on the other survivor", func() bool {
		return hasDevice(leader.testNode, "after-second-failure") && hasDevice(n4, "after-second-failure")
	})
}

// TestRemoveRefusals covers what removal refuses, on the leader and through
// a follower, and the transfer of leadership that lets the leader go.
func TestRemoveRefusals(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	follower := followers(hubs, leader)[0]
	ctx := t.Context()

	if _, err := leader.RemoveMember(ctx, leader.ID()); !errors.Is(err, ErrRemoveLeader) {
		t.Errorf("leader removes itself: err = %v, want ErrRemoveLeader", err)
	}
	if _, err := follower.RemoveMember(ctx, leader.ID()); err == nil || !strings.Contains(err.Error(), "transfer-leadership") {
		t.Errorf("remove the leader through a follower: err = %v, want the transfer-leadership hint", err)
	}
	for _, h := range []*testHub{leader, follower} {
		if _, err := h.RemoveMember(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("remove an unknown ID on %s: err = %v, want ErrNotFound", h.ID(), err)
		}
	}
	if _, err := follower.RemoveMember(ctx, "Not An ID"); err == nil {
		t.Error("remove an invalid ID: no error")
	}
	if got := voters(t, leader.testNode); len(got) != 3 {
		t.Fatalf("a refused removal changed the voters: %v", got)
	}

	// Transfer leadership to the follower, through it; then the old leader
	// can be removed.
	if err := follower.TransferLeadership(ctx, follower.ID()); err != nil {
		t.Fatalf("transfer leadership to %s: %v", follower.ID(), err)
	}
	if l := leaderHub(t, hubs); l != follower {
		t.Fatalf("leader after the transfer = %s, want %s", l.ID(), follower.ID())
	}
	if err := follower.TransferLeadership(ctx, follower.ID()); err == nil {
		t.Error("transfer leadership to the leader itself: no error")
	}
	if k, err := follower.RemoveMember(ctx, leader.ID()); err != nil || k != 0 {
		// The test hubs never recorded their certificates: none to revoke.
		t.Fatalf("remove the former leader: %d, %v", k, err)
	}
	if got := voters(t, follower.testNode); len(got) != 2 {
		t.Fatalf("voters after removing the former leader = %v", got)
	}
}

func TestVoterRemovable(t *testing.T) {
	n := &Node{cfg: Config{NodeID: "n1"}}
	n.members.failing = map[raft.ServerID]bool{"n3": true}
	srv := func(id string, s raft.ServerSuffrage) raft.Server {
		return raft.Server{ID: raft.ServerID(id), Suffrage: s}
	}
	tests := []struct {
		name    string
		servers []raft.Server
		remove  string
		want    error
	}{
		{"last voter", []raft.Server{srv("n1", raft.Nonvoter), srv("n2", raft.Voter)}, "n2", ErrLastVoter},
		{"dead voter of three", []raft.Server{srv("n1", raft.Voter), srv("n2", raft.Voter), srv("n3", raft.Voter)}, "n3", nil},
		{"live voter next to a dead one", []raft.Server{srv("n1", raft.Voter), srv("n2", raft.Voter), srv("n3", raft.Voter)}, "n2", ErrQuorumAtRisk},
		{"voter of five, one dead", []raft.Server{
			srv("n1", raft.Voter), srv("n2", raft.Voter), srv("n3", raft.Voter), srv("n4", raft.Voter), srv("n5", raft.Voter),
		}, "n2", nil},
		{"the other voter of two", []raft.Server{srv("n1", raft.Voter), srv("n2", raft.Voter)}, "n2", nil},
		{"non-voters do not count", []raft.Server{srv("n1", raft.Voter), srv("n2", raft.Voter), srv("n3", raft.Voter), srv("n4", raft.Nonvoter)}, "n2", ErrQuorumAtRisk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := n.voterRemovable(tt.servers, raft.ServerID(tt.remove)); !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestRevokedHubRefusedOnClusterService presents a member's revoked hub
// certificate to every hub-authenticated ClusterService call.
func TestRevokedHubRefusedOnClusterService(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	member := followers(hubs, leader)[0]
	revoked := hubCert(t, leader.ca, member.ID())
	if err := leader.st.Hubs().RecordCert(t.Context(), pki.SerialString(revoked.Leaf), member.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.st.Hubs().RevokeCerts(t.Context(), member.ID(), time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd, err := store.EncodeCommand(store.SetHubURL{NodeID: "evil", AgentURL: "https://evil:7443"})
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]func(clusterv1connect.ClusterServiceClient) error{
		"Forward": func(c clusterv1connect.ClusterServiceClient) error {
			_, err := c.Forward(t.Context(), connect.NewRequest(&clusterv1.ForwardRequest{Command: cmd}))
			return err
		},
		"Promote": func(c clusterv1connect.ClusterServiceClient) error {
			_, err := c.Promote(t.Context(), connect.NewRequest(&clusterv1.PromoteRequest{NodeId: member.ID()}))
			return err
		},
		"RemoveMember": func(c clusterv1connect.ClusterServiceClient) error {
			_, err := c.RemoveMember(t.Context(), connect.NewRequest(&clusterv1.RemoveMemberRequest{NodeId: "ghost"}))
			return err
		},
		"TransferLeadership": func(c clusterv1connect.ClusterServiceClient) error {
			_, err := c.TransferLeadership(t.Context(), connect.NewRequest(&clusterv1.TransferLeadershipRequest{NodeId: "ghost"}))
			return err
		},
	}
	client := clusterv1connect.NewClusterServiceClient(tlsClient(leader.ca, revoked), leader.url)
	for name, call := range calls {
		if got := connect.CodeOf(call(client)); got != connect.CodePermissionDenied {
			t.Errorf("%s with a revoked certificate: code = %v, want %v", name, got, connect.CodePermissionDenied)
		}
	}
	if urls, _ := leader.st.Hubs().AgentURLs(t.Context()); urls["evil"] != "" {
		t.Fatal("a forward with a revoked certificate was applied")
	}
	// Revocation is by serial: another certificate of the same member works.
	fresh := clusterv1connect.NewClusterServiceClient(tlsClient(leader.ca, hubCert(t, leader.ca, member.ID())), leader.url)
	if err := calls["Forward"](fresh); err != nil {
		t.Fatalf("forward with an unrevoked certificate of the member: %v", err)
	}
}

// TestRenewedNodeCertIsRecorded starts a node whose certificate is about to
// expire: it renews it at start, and RecordNodeCert records the new serial.
func TestRenewedNodeCertIsRecorded(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "n1")
	if err != nil {
		t.Fatal(err)
	}
	// Issued so that it expires in 10 days: inside the 30-day renewal window.
	old, err := ca.SignHubCSR(csr, "n1", time.Now().Add(-pki.HubCertValidity+10*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNodeCert(filepath.Join(dir, RaftDir), old, key); err != nil {
		t.Fatal(err)
	}
	n := startNode(t, ca, "n1", dir, "", true)
	leaderOf(t, n)
	if pki.SerialString(n.cert) == pki.SerialString(old) {
		t.Fatal("the node kept a certificate about to expire")
	}
	if err := n.st.Hubs().RecordCert(t.Context(), pki.SerialString(old), "n1"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), waitFor)
	defer cancel()
	n.RecordNodeCert(ctx)
	certs, err := n.st.Hubs().Certs(t.Context(), "n1")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || !containsSerial(certs, pki.SerialString(n.cert)) {
		t.Fatalf("recorded certs = %+v, want the old and the renewed %s", certs, pki.SerialString(n.cert))
	}
	// A revoked node certificate is not recorded again or un-revoked.
	if _, err := n.st.Hubs().RevokeCerts(t.Context(), "n1", time.Now()); err != nil {
		t.Fatal(err)
	}
	n.RecordNodeCert(ctx)
	if err := n.st.Hubs().CheckCert(t.Context(), pki.SerialString(n.cert)); !errors.Is(err, store.ErrCertRevoked) {
		t.Errorf("CheckCert after RecordNodeCert of a revoked cert = %v, want ErrCertRevoked", err)
	}
}

// TestRejoinAfterRemoval joins a hub, removes it once it is dead and joins a
// new hub under the same node ID: removal frees the ID, the leader records
// each certificate it signs, and only the old one is revoked.
func TestRejoinAfterRemoval(t *testing.T) {
	ca := newTestCA(t)
	n1 := startNode(t, ca, "n1", "", "", true)
	leaderOf(t, n1)
	srv := joinServer(t, n1, ca)
	n2 := joinAndStart(t, srv.URL, joinToken(t, n1, ca, time.Now().Add(time.Hour)), "n2")
	n3 := joinAndStart(t, srv.URL, joinToken(t, n1, ca, time.Now().Add(time.Hour)), "n3")
	oldSerial := pki.SerialString(n3.cert)
	if certs, err := n1.st.Hubs().Certs(t.Context(), "n3"); err != nil || len(certs) != 1 || certs[0].Serial != oldSerial {
		t.Fatalf("certs of n3 after its join = %+v, %v; want its node certificate", certs, err)
	}

	// While n3 is a member, its ID is taken.
	dir := t.TempDir()
	err := Join(t.Context(), JoinParams{
		URL: srv.URL, Token: joinToken(t, n1, ca, time.Now().Add(time.Hour)), DataDir: dir, NodeID: "n3", RaftAddress: freeAddr(t),
	})
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("join a member's ID: err = %v, want AlreadyExists", err)
	}

	n3.stop()
	eventually(t, "the leader to see n3 fail", func() bool { return n1.members.isFailing("n3") })
	if k, err := n1.RemoveMember(t.Context(), "n3"); err != nil || k != 1 {
		t.Fatalf("RemoveMember(n3) = %d, %v", k, err)
	}
	again := joinAndStart(t, srv.URL, joinToken(t, n1, ca, time.Now().Add(time.Hour)), "n3")
	if got := voters(t, n1); len(got) != 3 {
		t.Fatalf("voters after the rejoin = %v", got)
	}
	if err := n1.st.Hubs().CheckCert(t.Context(), oldSerial); !errors.Is(err, store.ErrCertRevoked) {
		t.Errorf("old certificate of n3: %v, want revoked", err)
	}
	if err := n1.st.Hubs().CheckCert(t.Context(), pki.SerialString(again.cert)); err != nil {
		t.Errorf("new certificate of n3: %v, want valid", err)
	}
	upsert(t, n1, "after-rejoin")
	eventually(t, "the write on the rejoined n3", func() bool { return hasDevice(again, "after-rejoin") && hasDevice(n2, "after-rejoin") })
}

func containsSerial(certs []store.HubCert, serial string) bool {
	for _, c := range certs {
		if c.Serial == serial {
			return true
		}
	}
	return false
}
