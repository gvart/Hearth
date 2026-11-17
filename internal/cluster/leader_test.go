// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// silentDevice stores an online device last seen long ago.
func silentDevice(t *testing.T, h *testHub, id string) {
	t.Helper()
	old := time.Now().Add(-time.Hour)
	if err := h.st.Devices().Upsert(t.Context(), store.Device{
		ID: id, Name: id, FirstSeen: old, LastSeen: old, Status: store.StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}
}

func statusOn(h *testHub, id string) string {
	d, err := h.st.Devices().Get(context.Background(), id)
	if err != nil {
		return ""
	}
	return d.Status
}

func TestSweeperRunsOnlyOnTheLeaderAndMovesOnFailover(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: 600 * time.Millisecond, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	silentDevice(t, leader, "quiet-1")
	eventually(t, "quiet-1 offline everywhere", func() bool {
		for _, h := range hubs {
			if statusOn(h, "quiet-1") != store.StatusOffline {
				return false
			}
		}
		return true
	})
	for _, h := range hubs {
		got := len(h.eventsOf(hub.EventDeviceOffline))
		if want := map[bool]int{true: 1, false: 0}[h == leader]; got != want {
			t.Errorf("%s published %d offline events, want %d (only the leader sweeps)", h.ID(), got, want)
		}
	}

	leader.kill()
	next := leaderHub(t, hubs)
	silentDevice(t, next, "quiet-2")
	eventually(t, "the new leader to sweep quiet-2", func() bool { return statusOn(next, "quiet-2") == store.StatusOffline })
	if len(next.eventsOf(hub.EventDeviceOffline)) != 1 {
		t.Errorf("new leader %s: offline events for %v", next.ID(), eventIDs(next.eventsOf(hub.EventDeviceOffline)))
	}
	// Give the remaining follower several sweep periods: it stays quiet.
	time.Sleep(300 * time.Millisecond)
	for _, h := range followers(hubs, next) {
		if n := len(h.eventsOf(hub.EventDeviceOffline)); n != 0 {
			t.Errorf("follower %s published %d offline events", h.ID(), n)
		}
	}
	for _, h := range hubs {
		if strings.Contains(h.logs.String(), "not the cluster leader") {
			t.Errorf("%s logged a not-leader error:\n%s", h.ID(), h.logs.String())
		}
	}
}

func TestStreamsEndWithNotLeaderOnStepDown(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: 5 * time.Second, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	cert := enrollTestDevice(t, leader, "pi")
	agent := runTestAgent(t, []*testHub{leader}, "pi", cert, 50*time.Millisecond, 50*time.Millisecond)
	eventually(t, "agent on the leader", func() bool { return agent.url() == leader.url })

	if err := leader.raft.LeadershipTransfer().Error(); err != nil {
		t.Fatalf("LeadershipTransfer: %v", err)
	}
	eventually(t, "the stream to end", func() bool { return agent.url() != leader.url })
	nl := notLeaderDetail(agent.err())
	if nl == nil {
		t.Fatalf("stream ended with %v, want FailedPrecondition with a NotLeader detail", agent.err())
	}
	if len(nl.GetHubs()) != 3 {
		t.Errorf("NotLeader.hubs = %v, want all 3 hubs", nl.GetHubs())
	}
	// The agent's next attempts reach the new leader, through the hint or the
	// old leader's refusal.
	next := leaderHub(t, hubs)
	if next == leader {
		t.Fatal("leadership did not move")
	}
}

// apiClient is an HTTPS client of a hub's JSON API with a cookie jar.
type apiClient struct {
	t    *testing.T
	base string
	c    *http.Client
	cook []*http.Cookie
}

func (a *apiClient) do(method, path string, body any) (int, []byte) {
	a.t.Helper()
	var r *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(a.t.Context(), method, a.base+path, r)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range a.cook {
		req.AddCookie(c)
	}
	resp, err := a.c.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if cs := resp.Cookies(); len(cs) > 0 {
		a.cook = cs
	}
	return resp.StatusCode, buf.Bytes()
}

func TestFollowerWritesAreForwarded(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: 5 * time.Second, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	f := followers(hubs, leader)[0]
	ctx := t.Context()
	if err := hub.SetAdminPassword(ctx, leader.st, leader.pol, "test", "correct horse"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "password on the follower", func() bool {
		_, err := f.st.Admin().PasswordHash(ctx)
		return err == nil
	})

	// Login (a session write and an audit entry) through the follower's API.
	api := &apiClient{t: t, base: f.url, c: tlsClient(f.ca)}
	if code, body := api.do(http.MethodPost, "/api/v1/login", map[string]string{"password": "correct horse"}); code != http.StatusOK {
		t.Fatalf("login on a follower: %d %s", code, body)
	}
	secret := ""
	for _, c := range api.cook {
		if c.Name == hub.SecureSessionCookie {
			secret = c.Value
		}
	}
	for _, h := range hubs {
		eventually(t, "the session on "+h.ID(), func() bool {
			_, err := h.st.Admin().CheckSession(ctx, secret, time.Now())
			return err == nil
		})
	}

	// An enrollment token created on the follower is usable on every hub.
	code, body := api.do(http.MethodPost, "/api/v1/tokens", map[string]string{"ttl": "10m"})
	if code != http.StatusCreated {
		t.Fatalf("token create on a follower: %d %s", code, body)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatal(err)
	}
	parsed, err := pki.ParseToken(tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	other := followers(hubs, leader)[1]
	if _, err := other.st.Tokens().Consume(ctx, parsed.Secret, time.Now()); err != nil {
		t.Fatalf("consume the follower's token through %s: %v", other.ID(), err)
	}

	// A CLI write through a follower's control socket (device revoke).
	serial := pki.SerialString(enrollTestDevice(t, leader, "pi").Leaf)
	eventually(t, "pi on the follower", func() bool { return statusOn(f, "pi") != "" })
	cc := serveControl(t, f.testNode)
	cli, err := store.Open(ctx, filepath.Join(t.TempDir(), "cli.db"), store.WithApplier(func(*store.Store) store.Applier { return cc }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	if n, err := cli.Certs().RevokeDevice(ctx, "pi", time.Now()); err != nil || n != 1 {
		t.Fatalf("revoke through the follower's socket = %d, %v", n, err)
	}
	for _, h := range hubs {
		eventually(t, "the revocation on "+h.ID(), func() bool {
			return errors.Is(h.st.Certs().Check(ctx, serial, "pi"), store.ErrCertRevoked)
		})
	}

	// Every write was audited where the user asked, and replicated.
	for _, h := range hubs {
		eventually(t, "audit on "+h.ID(), func() bool {
			es, _ := h.st.Audit().List(ctx, 50)
			seen := map[string]bool{}
			for _, e := range es {
				seen[e.Action] = true
			}
			return seen["admin.login"] && seen["token.create"]
		})
	}
	// A domain error travels back through the forward unchanged.
	if _, err := f.st.Tokens().Consume(ctx, parsed.Secret, time.Now()); !errors.Is(err, store.ErrTokenUsed) {
		t.Errorf("reused token through the follower: err = %v, want ErrTokenUsed", err)
	}
}

func TestForwardRejectsNonHubCallers(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: 5 * time.Second, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	cmd, err := store.EncodeCommand(store.SetHubURL{NodeID: "evil", AgentURL: "https://evil:7443"})
	if err != nil {
		t.Fatal(err)
	}
	forward := func(url string, certs ...tls.Certificate) error {
		c := clusterv1connect.NewClusterServiceClient(tlsClient(leader.ca, certs...), url)
		_, err := c.Forward(t.Context(), connect.NewRequest(&clusterv1.ForwardRequest{Command: cmd}))
		return err
	}
	stranger := hubCert(t, leader.ca, "stranger")
	member := hubCert(t, leader.ca, followers(hubs, leader)[0].ID())

	tests := []struct {
		name  string
		url   string
		certs []tls.Certificate
		want  connect.Code
	}{
		{"no certificate", leader.url, nil, connect.CodeUnauthenticated},
		{"device certificate", leader.url, []tls.Certificate{enrollTestDevice(t, leader, "pi")}, connect.CodePermissionDenied},
		{"hub certificate of a non-member", leader.url, []tls.Certificate{stranger}, connect.CodePermissionDenied},
		{"member on a follower", followers(hubs, leader)[0].url, []tls.Certificate{member}, connect.CodeFailedPrecondition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := connect.CodeOf(forward(tt.url, tt.certs...)); got != tt.want {
				t.Errorf("code = %v, want %v", got, tt.want)
			}
		})
	}
	if urls, _ := leader.st.Hubs().AgentURLs(t.Context()); urls["evil"] != "" {
		t.Fatal("a rejected forward was applied")
	}
	if err := forward(leader.url, member); err != nil {
		t.Fatalf("member forward: %v", err)
	}
}

func TestForwardWithoutLeaderFailsInBoundedTime(t *testing.T) {
	const wait = time.Second
	hubs := startHubs(t, hubOpts{offlineAfter: 5 * time.Second, flushEvery: time.Minute, forwardWait: wait})
	leader := leaderHub(t, hubs)
	last := followers(hubs, leader)[0]
	if err := hub.SetAdminPassword(t.Context(), leader.st, leader.pol, "test", "correct horse"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "password on "+last.ID(), func() bool {
		_, err := last.st.Admin().PasswordHash(t.Context())
		return err == nil
	})
	for _, h := range hubs {
		if h != last {
			h.kill()
		}
	}
	eventually(t, "the lone hub to lose its leader", func() bool { return !last.IsLeader() && last.Leader().ID == "" })

	start := time.Now()
	err := last.st.Tokens().Create(t.Context(), "s", nil, time.Now().Add(time.Hour))
	took := time.Since(start)
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("write without a leader: err = %v, want ErrUnavailable", err)
	}
	if took < wait || took > wait+2*time.Second {
		t.Errorf("gave up after %v, want about %v", took, wait)
	}

	// The API answers 503 and says nothing was written.
	api := &apiClient{t: t, base: last.url, c: tlsClient(last.ca)}
	code, body := api.do(http.MethodPost, "/api/v1/login", map[string]string{"password": "correct horse"})
	if code != http.StatusServiceUnavailable || !strings.Contains(string(body), "cluster_unavailable") {
		t.Errorf("login without a leader: %d %s, want 503", code, body)
	}
}

func TestPresenceBatchingFlushesAndReplicates(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: 5 * time.Second, flushEvery: 300 * time.Millisecond})
	leader := leaderHub(t, hubs)
	cert := enrollTestDevice(t, leader, "pi")
	const every = 20 * time.Millisecond
	agent := runTestAgent(t, []*testHub{leader}, "pi", cert, every, 50*time.Millisecond)
	eventually(t, "agent online", func() bool { return agent.url() == leader.url && statusOn(leader, "pi") == store.StatusOnline })

	before := leader.raft.LastIndex()
	start := time.Now()
	time.Sleep(time.Second)
	entries := leader.raft.LastIndex() - before
	heartbeats := int64(time.Since(start) / every)
	if int64(entries)*4 > heartbeats { //nolint:gosec // a handful of log entries
		t.Errorf("%d raft entries for ~%d heartbeats: last_seen is not batched", entries, heartbeats)
	}

	// The API serves the live value; the stored one trails by at most a flush.
	d, err := leader.st.Devices().Get(t.Context(), "pi")
	if err != nil {
		t.Fatal(err)
	}
	live := leader.reg.Live(d)
	if age := time.Since(d.LastSeen); age > time.Second {
		t.Errorf("stored last_seen is %v old with a 300ms flush", age)
	}
	if age := time.Since(live.LastSeen); age > 200*time.Millisecond {
		t.Errorf("live last_seen is %v old with heartbeats every %v", age, every)
	}

	// Every hub applied the same batches: identical device rows.
	time.Sleep(100 * time.Millisecond)
	if err := leader.reg.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	want, err := leader.st.Devices().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range followers(hubs, leader) {
		eventually(t, h.ID()+" to apply the last batch", func() bool {
			got, err := h.st.Devices().List(t.Context())
			if err != nil {
				return false
			}
			// Heartbeats continue; compare up to the last flush.
			return len(got) == len(want) && got[0].LastSeen.Compare(want[0].LastSeen) >= 0
		})
	}
	// Stop the agent's heartbeats from moving last_seen, then compare exactly.
	leader.srv.CloseClientConnections()
	eventually(t, "the agent to drop", func() bool { return agent.url() == "" })
	if err := leader.reg.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	want, _ = leader.st.Devices().List(t.Context())
	for _, h := range followers(hubs, leader) {
		eventually(t, h.ID()+" to match the leader", func() bool {
			got, _ := h.st.Devices().List(t.Context())
			return reflect.DeepEqual(got, want)
		})
	}
}

func TestNoFlapOnLeaderChange(t *testing.T) {
	const offlineAfter = 1500 * time.Millisecond
	// last_seen is never flushed during the test, so the stored value is
	// stale by more than offlineAfter when the leader dies.
	hubs := startHubs(t, hubOpts{offlineAfter: offlineAfter, flushEvery: time.Hour})
	leader := leaderHub(t, hubs)
	ids := []string{"pi", "nas", "router"}
	var agents []*testAgent
	for _, id := range ids {
		// Agents come back after half an offlineAfter: after the new
		// leader's first sweeps, well within its grace period.
		agents = append(agents, runTestAgent(t, hubs, id, enrollTestDevice(t, leader, id), 100*time.Millisecond, offlineAfter/2))
	}
	eventually(t, "every agent on the leader", func() bool {
		for _, a := range agents {
			if a.url() != leader.url {
				return false
			}
		}
		return true
	})
	time.Sleep(2 * offlineAfter)

	leader.kill()
	next := leaderHub(t, hubs)
	eventually(t, "every agent on the new leader", func() bool {
		for _, a := range agents {
			if a.url() != next.url {
				return false
			}
		}
		return true
	})
	// Well past one offlineAfter of the new leadership.
	deadline := time.Now().Add(2 * offlineAfter)
	for time.Now().Before(deadline) {
		for _, id := range ids {
			if s := statusOn(next, id); s != store.StatusOnline {
				t.Fatalf("%s is %s on the new leader", id, s)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, h := range hubs {
		if h.down {
			continue
		}
		if off := h.eventsOf(hub.EventDeviceOffline); len(off) != 0 {
			t.Errorf("%s published offline events for %v", h.ID(), eventIDs(off))
		}
		if on := h.eventsOf(hub.EventDeviceOnline); h == next && len(on) != 0 {
			t.Errorf("new leader published online events (a flap) for %v", eventIDs(on))
		}
	}
}

func eventIDs(es []hub.Event) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Device.ID)
	}
	return out
}

func TestAgentURL(t *testing.T) {
	n := &Node{cfg: Config{NodeID: "a", AgentURL: "https://hub-a.lan:7443", AgentPort: "7443"}}
	urls := map[string]string{"a": "https://stale:1", "b": "https://hub-b.lan:8443"}
	tests := []struct{ id, raftAddr, want string }{
		{"a", "10.0.0.1:7444", "https://hub-a.lan:7443"}, // this hub: its own config
		{"b", "10.0.0.2:7444", "https://hub-b.lan:8443"}, // recorded
		{"c", "10.0.0.3:7444", "https://10.0.0.3:7443"},  // not recorded yet: derived
		{"d", "bad", ""},
	}
	for _, tt := range tests {
		if got := n.agentURL(urls, tt.id, tt.raftAddr); got != tt.want {
			t.Errorf("agentURL(%s) = %q, want %q", tt.id, got, tt.want)
		}
	}
	n.cfg.AgentPort = ""
	if got := n.agentURL(urls, "c", "10.0.0.3:7444"); got != "" {
		t.Errorf("without a fallback port: %q, want unknown", got)
	}
}
