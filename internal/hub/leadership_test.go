// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// fakeLeadership is a Leadership whose answers the test sets.
type fakeLeadership struct {
	leader atomic.Bool
	url    string
	urls   []string
}

func (f *fakeLeadership) IsLeader() bool         { return f.leader.Load() }
func (f *fakeLeadership) LeaderAgentURL() string { return f.url }
func (f *fakeLeadership) AgentURLs() []string    { return f.urls }

var clusterURLs = []string{"https://hub-a:7443", "https://hub-b:7443", "https://hub-c:7443"}

// follower is a hub that is not the leader; hub-b leads.
func follower() *fakeLeadership {
	return &fakeLeadership{url: clusterURLs[1], urls: clusterURLs}
}

// assertNotLeader checks err is FailedPrecondition with a NotLeader detail
// naming the fake's leader and hubs.
func assertNotLeader(t *testing.T, err error, lead *fakeLeadership) {
	t.Helper()
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v (%v), want FailedPrecondition", got, err)
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("%v is not a connect error", err)
	}
	for _, d := range cerr.Details() {
		v, err := d.Value()
		if err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		if nl, ok := v.(*agentv1.NotLeader); ok {
			if nl.GetLeaderUrl() != lead.url || !slices.Equal(nl.GetHubs(), lead.urls) {
				t.Errorf("NotLeader = %v, want leader %s hubs %v", nl, lead.url, lead.urls)
			}
			return
		}
	}
	t.Fatalf("no NotLeader detail in %v", err)
}

func TestConnectFollowerRefuses(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	lead := follower()
	client, st := newStreamClient(t, "dev-1", lead)

	stream := client.Connect(ctx)
	_ = stream.Send(hello(ProtocolMajor)) // may fail: the hub refuses without reading
	_, err := stream.Receive()
	assertNotLeader(t, err, lead)

	dev, err := st.Devices().Get(t.Context(), "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Status != store.StatusUnknown || dev.OS != "" {
		t.Errorf("follower wrote to the registry: status=%q os=%q", dev.Status, dev.OS)
	}
}

func TestConnectWelcomeListsHubs(t *testing.T) {
	t.Parallel()
	leader := follower()
	leader.leader.Store(true)
	tests := []struct {
		name string
		lead Leadership
		want []string
	}{
		{"single hub", nil, nil},
		{"cluster leader", leader, clusterURLs},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, _ := newStreamClient(t, "dev-1", tt.lead)
			stream := client.Connect(ctx)
			if err := stream.Send(hello(ProtocolMajor)); err != nil {
				t.Fatal(err)
			}
			msg, err := stream.Receive()
			if err != nil {
				t.Fatal(err)
			}
			if got := msg.GetWelcome().GetHubs(); !slices.Equal(got, tt.want) {
				t.Errorf("Welcome.hubs = %v, want %v", got, tt.want)
			}
			if err := stream.CloseRequest(); err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Receive(); !errors.Is(err, io.EOF) {
				t.Fatalf("after close: %v, want EOF", err)
			}
		})
	}
}

func TestLeadershipOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cfg        Config
		wantURLs   []string
		wantLeader bool
	}{
		{"single hub", Config{}, nil, true},
		{"single hub ignores agent hosts", Config{AgentHosts: []string{"hub.lan", "localhost"}, AgentPort: "8443"}, nil, true},
		{"cluster", Config{AgentHosts: []string{"hub.lan"}, Leadership: follower()}, clusterURLs, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l := leadershipOf(tt.cfg)
			if l.IsLeader() != tt.wantLeader {
				t.Errorf("IsLeader = %v, want %v", l.IsLeader(), tt.wantLeader)
			}
			if got := l.AgentURLs(); !slices.Equal(got, tt.wantURLs) {
				t.Errorf("AgentURLs = %v, want %v", got, tt.wantURLs)
			}
		})
	}
}

func TestEnrollFollowerRefuses(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := pki.NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Tokens().Create(t.Context(), tok.Secret, nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "pi")
	if err != nil {
		t.Fatal(err)
	}
	lead := follower()
	e := NewEnroller(st, ca, policy.New(st.Audit()), slog.New(slog.DiscardHandler))
	e.leadership = lead
	req := &agentv1.EnrollRequest{TokenSecret: tok.Secret, Csr: csr, Hostname: "pi"}

	_, err = e.Enroll(t.Context(), connect.NewRequest(req))
	assertNotLeader(t, err, lead)
	if devs, err := st.Devices().List(t.Context()); err != nil || len(devs) != 0 {
		t.Fatalf("follower enrolled a device: %v (err %v)", devs, err)
	}

	// The refused attempt did not burn the token: the leader accepts it.
	lead.leader.Store(true)
	if _, err := e.Enroll(t.Context(), connect.NewRequest(req)); err != nil {
		t.Fatalf("Enroll on the leader: %v", err)
	}
}
