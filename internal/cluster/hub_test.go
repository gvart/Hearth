// SPDX-License-Identifier: AGPL-3.0-only

package cluster

// In-process clusters of whole hubs: a Raft node, the hub's registry running
// its leader-only services, and the hub's TLS handler (agent services, JSON
// API, ClusterService) on a loopback httptest server per node.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// hubOpts tunes a test hub cluster.
type hubOpts struct {
	offlineAfter time.Duration
	flushEvery   time.Duration
	forwardWait  time.Duration
}

// testHub is one hub of an in-process cluster.
type testHub struct {
	*testNode
	ca     *pki.CA
	reg    *hub.Registry
	pol    *policy.Engine
	srv    *httptest.Server
	url    string
	logs   *lockedBuffer
	stopRS context.CancelFunc
	rsDone chan struct{}

	mu     sync.Mutex
	events []hub.Event
}

// lockedBuffer collects log output from concurrent goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// startHubs forms a 3-voter cluster of hubs whose writes are forwarded from
// followers, and records each hub's agent URL in the cluster.
func startHubs(t *testing.T, o hubOpts) []*testHub {
	t.Helper()
	ca := newTestCA(t)
	if o.forwardWait == 0 {
		o.forwardWait = time.Second
	}
	tune := func(c *Config) { c.ForwardWait = o.forwardWait }
	bind := (*Node).BindForwarding
	n1 := startNodeBound(t, ca, "n1", "", "", true, bind, tune)
	leaderOf(t, n1)
	n2 := startNodeBound(t, ca, "n2", "", "", false, bind, tune)
	n3 := startNodeBound(t, ca, "n3", "", "", false, bind, tune)
	addVoter(t, n1, n2)
	addVoter(t, n1, n3)
	hubs := []*testHub{startHub(t, n1, ca, o), startHub(t, n2, ca, o), startHub(t, n3, ca, o)}
	for _, h := range hubs {
		if err := n1.st.Hubs().SetAgentURL(t.Context(), h.ID(), h.url); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to know every hub URL", func() bool { return len(h.AgentURLs()) == 3 })
	}
	return hubs
}

func startHub(t *testing.T, n *testNode, ca *pki.CA, o hubOpts) *testHub {
	t.Helper()
	h := &testHub{testNode: n, ca: ca, logs: &lockedBuffer{}, rsDone: make(chan struct{})}
	log := slog.New(slog.NewTextHandler(h.logs, nil))
	if os.Getenv("HEARTH_TEST_RAFT_LOG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil)).With("hub", n.ID())
	}
	h.reg = hub.NewRegistry(hub.RegistryConfig{
		Store: n.st, Log: log, OfflineAfter: o.offlineAfter, SeenFlushInterval: o.flushEvery, Replicated: true,
	})
	h.pol = policy.New(n.st.Audit())
	events, unsubscribe := h.reg.Subscribe()
	go func() {
		for e := range events {
			h.mu.Lock()
			h.events = append(h.events, e)
			h.mu.Unlock()
		}
	}()

	changed := make(chan struct{}, 1)
	n.OnLeaderChange(func(LeaderInfo) {
		select {
		case changed <- struct{}{}:
		default:
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	h.stopRS = cancel
	go func() {
		defer close(h.rsDone)
		_ = h.reg.RunReplicated(ctx, n.Node, changed)
	}()

	cfg := hub.Config{
		Store: n.st, CA: ca, Policy: h.pol, Log: log, HeartbeatInterval: time.Second,
		Registry: h.reg, Leadership: n.Node, AgentHosts: []string{"127.0.0.1"},
	}
	web := http.NewServeMux()
	web.Handle("/", hub.NewHTTPHandler(cfg))
	web.Handle(NewJoinServer(n.Node, n.st, ca, h.pol, log).Handler())
	cert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h.srv = httptest.NewUnstartedServer(hub.NewTLSHandler(cfg, web))
	h.srv.TLS = hub.TLSConfig(ca, cert)
	h.srv.EnableHTTP2 = true
	h.srv.StartTLS()
	h.url = h.srv.URL
	// Runs before the node's own cleanup: the registry stops first.
	t.Cleanup(func() {
		h.kill()
		unsubscribe()
	})
	return h
}

// kill takes the hub down as a crash would look to the others: connections
// drop and Raft stops before the registry could flush anything.
func (h *testHub) kill() {
	if h.down {
		return
	}
	h.srv.CloseClientConnections()
	h.stop()
	h.stopRS()
	<-h.rsDone
	h.srv.Close()
}

func (h *testHub) eventsOf(typ string) []hub.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []hub.Event
	for _, e := range h.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func leaderHub(t *testing.T, hubs []*testHub) *testHub {
	t.Helper()
	var nodes []*testNode
	for _, h := range hubs {
		nodes = append(nodes, h.testNode)
	}
	l := leaderOf(t, nodes...)
	for _, h := range hubs {
		if h.testNode == l {
			return h
		}
	}
	return nil
}

func followers(hubs []*testHub, leader *testHub) []*testHub {
	var out []*testHub
	for _, h := range hubs {
		if h != leader && !h.down {
			out = append(out, h)
		}
	}
	return out
}

// tlsClient trusts the hub CA and presents certs, if any.
func tlsClient(ca *pki.CA, certs ...tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: certs},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: tr}
}

// enrollTestDevice records a device and its certificate, as enrollment
// does, and returns the device's client certificate.
func enrollTestDevice(t *testing.T, h *testHub, id string) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := h.ca.SignClientCSR(csr, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := h.st.Devices().Upsert(t.Context(), store.Device{
		ID: id, Name: id, Hostname: id, FirstSeen: now, LastSeen: now, Status: store.StatusUnknown,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Certs().Create(t.Context(), pki.SerialString(cert), id); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

// testAgent is a minimal agent: it connects to a hub, follows NotLeader to
// the leader (or tries the next hub after retry), and heartbeats every
// interval.
type testAgent struct {
	connectedTo atomic.Value // string: the hub URL of the current stream
	welcomes    atomic.Int32
	mu          sync.Mutex
	lastErr     error
}

func (a *testAgent) url() string {
	u, _ := a.connectedTo.Load().(string)
	return u
}

func (a *testAgent) err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

func runTestAgent(t *testing.T, hubs []*testHub, id string, cert tls.Certificate, every, retry time.Duration) *testAgent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	client := tlsClient(hubs[0].ca, cert)
	a := &testAgent{}
	a.connectedTo.Store("")
	go func() {
		defer close(done)
		next := hubs[0].url
		i := 0
		for ctx.Err() == nil {
			err := a.session(ctx, agentv1connect.NewAgentServiceClient(client, next), next, id, every)
			a.connectedTo.Store("")
			a.mu.Lock()
			a.lastErr = err
			a.mu.Unlock()
			if nl := notLeaderDetail(err); nl != nil && nl.GetLeaderUrl() != "" && nl.GetLeaderUrl() != next {
				next = nl.GetLeaderUrl()
				continue
			}
			i++
			next = hubs[i%len(hubs)].url
			select {
			case <-ctx.Done():
			case <-time.After(retry):
			}
		}
	}()
	return a
}

// session runs one stream until it fails.
func (a *testAgent) session(ctx context.Context, c agentv1connect.AgentServiceClient, url, id string, every time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream := c.Connect(ctx)
	defer func() { _ = stream.CloseRequest() }()
	_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ProtocolVersion: &agentv1.ProtocolVersion{Major: hub.ProtocolMajor},
		Hostname:        id, Os: "linux", Arch: "arm64", AgentVersion: "test",
	}}})
	msg, err := stream.Receive()
	if err != nil {
		return err
	}
	if msg.GetWelcome() == nil {
		return errors.New("no welcome")
	}
	a.welcomes.Add(1)
	a.connectedTo.Store(url)
	recvErr := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Receive(); err != nil {
				recvErr <- err
				cancel()
				return
			}
		}
	}()
	boot := time.Now().Add(-time.Hour)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case err := <-recvErr:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
				Ts: timestamppb.Now(), Uptime: durationpb.New(time.Since(boot)),
			}}})
		}
	}
}

// notLeaderDetail returns the NotLeader detail of err, if any.
func notLeaderDetail(err error) *agentv1.NotLeader {
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeFailedPrecondition {
		return nil
	}
	for _, d := range ce.Details() {
		if v, err := d.Value(); err == nil {
			if nl, ok := v.(*agentv1.NotLeader); ok {
				return nl
			}
		}
	}
	return nil
}
