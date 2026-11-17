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
	"runtime"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// joinServer serves node's ClusterService over TLS on loopback, the way the
// hub's TLS listener does (client certificates optional, from the CA).
func joinServer(t *testing.T, n *testNode, ca *pki.CA) *httptest.Server {
	t.Helper()
	cert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	path, h := NewJoinServer(n.Node, n.st, ca, policy.New(n.st.Audit()), testLogger(t)).Handler()
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func joinToken(t *testing.T, n *testNode, ca *pki.CA, expires time.Time) string {
	t.Helper()
	tok, err := pki.NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.st.JoinTokens().Create(t.Context(), tok.Secret, expires); err != nil {
		t.Fatal(err)
	}
	return tok.EncodeJoin()
}

// joinAndStart runs the whole join flow for a new hub and returns it once it
// is a voter.
func joinAndStart(t *testing.T, url, token, id string) *testNode {
	t.Helper()
	dir, addr := t.TempDir(), freeAddr(t)
	if err := Join(t.Context(), JoinParams{URL: url, Token: token, DataDir: dir, NodeID: id, RaftAddress: addr}); err != nil {
		t.Fatalf("Join %s: %v", id, err)
	}
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatalf("load the received CA: %v", err)
	}
	n := startNode(t, ca, id, dir, addr, false)
	eventually(t, id+" to catch up", func() bool { return n.raft.AppliedIndex() > 0 && n.Leader().ID != "" })
	if err := Promote(t.Context(), dir, id); err != nil {
		t.Fatalf("Promote %s: %v", id, err)
	}
	return n
}

func TestJoinFlow(t *testing.T) {
	ca := newTestCA(t)
	n1 := startNode(t, ca, "n1", "", "", true)
	leaderOf(t, n1)
	upsert(t, n1, "pi")
	srv := joinServer(t, n1, ca)

	n2 := joinAndStart(t, srv.URL, joinToken(t, n1, ca, time.Now().Add(time.Hour)), "n2")
	n3 := joinAndStart(t, srv.URL, joinToken(t, n1, ca, time.Now().Add(time.Hour)), "n3")

	st, err := n1.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Peers) != 3 {
		t.Fatalf("peers = %+v", st.Peers)
	}
	for _, p := range st.Peers {
		if p.Suffrage != "Voter" {
			t.Errorf("%s is %s after promotion", p.ID, p.Suffrage)
		}
	}
	for _, n := range []*testNode{n2, n3} {
		eventually(t, "pre-join data on "+n.ID(), func() bool { return hasDevice(n, "pi") })
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filepath.Join(n.dir, pki.CAKeyFile))
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s: ca.key mode = %o, want 600", n.ID(), perm)
			}
			info, err = os.Stat(filepath.Join(n.dir, RaftDir, nodeKeyFile))
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s: node.key mode = %o, want 600", n.ID(), perm)
			}
		}
		got, err := pki.LoadCACert(n.dir)
		if err != nil || pki.Fingerprint(got) != ca.Fingerprint() {
			t.Errorf("%s: CA = %v, %v; want the cluster's", n.ID(), got, err)
		}
	}
	// The joined cluster survives losing its founder.
	n1.stop()
	leader := leaderOf(t, n2, n3)
	upsert(t, leader, "after")

	// Every step was audited, on every node.
	entries, err := leader.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, e := range entries {
		if e.Decision == policy.Allow && e.Result == "ok" {
			actions[e.Action]++
		}
	}
	if actions[string(policy.ClusterJoin)] != 2 || actions[string(policy.ClusterPromote)] != 2 {
		t.Errorf("audited actions = %v, want 2 joins and 2 promotions", actions)
	}
}

func TestJoinRejects(t *testing.T) {
	ca := newTestCA(t)
	n1 := startNode(t, ca, "n1", "", "", true)
	leaderOf(t, n1)
	srv := joinServer(t, n1, ca)
	join := func(token, id string) (string, error) {
		dir := t.TempDir()
		err := Join(t.Context(), JoinParams{URL: srv.URL, Token: token, DataDir: dir, NodeID: id, RaftAddress: freeAddr(t)})
		return dir, err
	}
	wantCode := func(t *testing.T, err error, code connect.Code) {
		t.Helper()
		if connect.CodeOf(err) != code {
			t.Fatalf("err = %v, want %v", err, code)
		}
	}
	noSecrets := func(t *testing.T, dir string) {
		t.Helper()
		for _, f := range []string{pki.CAKeyFile, filepath.Join(RaftDir, nodeKeyFile)} {
			if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("rejected join left %s behind", f)
			}
		}
	}

	t.Run("wrong CA fingerprint", func(t *testing.T) {
		tok, err := pki.ParseJoinToken(joinToken(t, n1, ca, time.Now().Add(time.Hour)))
		if err != nil {
			t.Fatal(err)
		}
		tok.CAFingerprint = newTestCA(t).Fingerprint()
		dir, err := join(tok.EncodeJoin(), "evil")
		if !errors.Is(err, pki.ErrFingerprintMismatch) {
			t.Fatalf("err = %v, want ErrFingerprintMismatch", err)
		}
		noSecrets(t, dir)
	})
	t.Run("reused token", func(t *testing.T) {
		tok := joinToken(t, n1, ca, time.Now().Add(time.Hour))
		if _, err := join(tok, "first"); err != nil {
			t.Fatalf("first join: %v", err)
		}
		dir, err := join(tok, "second")
		wantCode(t, err, connect.CodeUnauthenticated)
		noSecrets(t, dir)
	})
	t.Run("expired token", func(t *testing.T) {
		dir, err := join(joinToken(t, n1, ca, time.Now().Add(-time.Second)), "late")
		wantCode(t, err, connect.CodeUnauthenticated)
		noSecrets(t, dir)
	})
	t.Run("enrollment token", func(t *testing.T) {
		tok, err := pki.NewToken(ca.Cert())
		if err != nil {
			t.Fatal(err)
		}
		if err := n1.st.Tokens().Create(t.Context(), tok.Secret, nil, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		// Re-wrapped as a join token, the secret is still unknown.
		_, err = join(tok.EncodeJoin(), "device")
		wantCode(t, err, connect.CodeUnauthenticated)
	})
	t.Run("node ID taken", func(t *testing.T) {
		_, err := join(joinToken(t, n1, ca, time.Now().Add(time.Hour)), "n1")
		wantCode(t, err, connect.CodeAlreadyExists)
	})
	t.Run("schema mismatch", func(t *testing.T) {
		token := joinToken(t, n1, ca, time.Now().Add(time.Hour))
		tok, err := pki.ParseJoinToken(token)
		if err != nil {
			t.Fatal(err)
		}
		key, err := pki.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		csr, err := pki.NewCSR(key, "newer")
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{TLSClientConfig: pki.PinnedTLSConfig(tok.CAFingerprint, "127.0.0.1")}
		defer transport.CloseIdleConnections()
		client := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: transport}, srv.URL)
		_, err = client.Join(t.Context(), connect.NewRequest(&clusterv1.JoinRequest{
			TokenSecret: tok.Secret, NodeId: "newer", RaftAddress: freeAddr(t), Csr: csr,
			SchemaVersion: store.SchemaVersion() + 1,
		}))
		wantCode(t, err, connect.CodeFailedPrecondition)
		// The rejection did not burn the token: a matching binary still joins.
		if _, err := join(token, "matching"); err != nil {
			t.Fatalf("join after a schema rejection: %v", err)
		}
	})
	t.Run("promote needs the node's certificate", func(t *testing.T) {
		transport := &http.Transport{TLSClientConfig: pki.PinnedTLSConfig(ca.Fingerprint(), "127.0.0.1")}
		defer transport.CloseIdleConnections()
		client := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: transport}, srv.URL)
		_, err := client.Promote(t.Context(), connect.NewRequest(&clusterv1.PromoteRequest{NodeId: "first"}))
		wantCode(t, err, connect.CodeUnauthenticated)
	})
}

func TestJoinOnFollowerNamesTheLeader(t *testing.T) {
	ca := newTestCA(t)
	nodes := threeNodes(t, ca)
	leader := leaderOf(t, nodes...)
	follower := nodes[1]
	if follower == leader {
		follower = nodes[2]
	}
	eventually(t, "follower to know the leader", func() bool { return follower.Leader().ID != "" })
	srv := joinServer(t, follower, ca)
	transport := &http.Transport{TLSClientConfig: pki.PinnedTLSConfig(ca.Fingerprint(), "127.0.0.1")}
	defer transport.CloseIdleConnections()
	client := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: transport}, srv.URL)
	_, err := client.Join(t.Context(), connect.NewRequest(&clusterv1.JoinRequest{TokenSecret: "x", NodeId: "n4", RaftAddress: "127.0.0.1:1"}))
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeFailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if ce.Meta().Get(metaLeaderID) != leader.ID() || ce.Meta().Get(metaLeaderAddr) != leader.Addr() {
		t.Errorf("leader meta = %v, want %s at %s", ce.Meta(), leader.ID(), leader.Addr())
	}
}

func TestNodeID(t *testing.T) {
	dir := t.TempDir()
	id, err := NodeID(dir, "", "My-Host.lan")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidNodeID(id); err != nil || len(id) < len("my-host-")+6 || id[:8] != "my-host-" {
		t.Fatalf("derived ID %q (%v)", id, err)
	}
	if again, err := NodeID(dir, "", "other"); err != nil || again != id {
		t.Fatalf("persisted ID = %q, %v; want %q", again, err, id)
	}
	if _, err := NodeID(dir, "different", ""); err == nil {
		t.Fatal("accepted a --node-id that differs from the data dir's")
	}
	for _, bad := range []string{"-x", "UPPER", "with space", "a/b", strings.Repeat("a", 64)} {
		if _, err := NodeID(t.TempDir(), bad, ""); err == nil {
			t.Errorf("accepted node ID %q", bad)
		}
	}
}
