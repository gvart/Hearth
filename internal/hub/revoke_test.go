// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// revokeFixture is an AgentStream with the certificate recheck wired as
// NewHandler wires it, served over h2c. Each client stands in for
// requireClientCert by putting a device ID and certificate serial into the
// request context.
type revokeFixture struct {
	st     *store.Store
	reg    *Registry
	h      http.Handler
	events <-chan Event
}

// newRevokeFixture enrolls dev-1 (serial 0a) and dev-2 (serial 0b). A
// replicated fixture is a clustered leader within its term; authority, if
// non-nil, replaces the registry's certAuthority (a follower or a hub
// catching up).
func newRevokeFixture(t *testing.T, replicated bool, authority func() error) *revokeFixture {
	t.Helper()
	st := newTestStore(t)
	for id, serial := range map[string]string{"dev-1": "0a", "dev-2": "0b"} {
		enrollDevice(t, st, id)
		if err := st.Certs().Create(t.Context(), serial, id); err != nil {
			t.Fatal(err)
		}
	}
	log := slog.New(slog.DiscardHandler)
	reg := NewRegistry(RegistryConfig{Store: st, Log: log, Replicated: replicated})
	lead := &fakeLeadership{}
	lead.leader.Store(true)
	if replicated {
		reg.startTerm()
	}
	as := NewAgentStream(log, time.Second, reg)
	as.leadership = lead
	as.certs, as.authority = st.Certs(), reg.certAuthority(lead)
	if authority != nil {
		as.authority = authority
	}
	_, h := agentv1connect.NewAgentServiceHandler(as)
	events, unsubscribe := reg.Subscribe()
	t.Cleanup(unsubscribe)
	return &revokeFixture{st: st, reg: reg, h: reg.endOnStepDown(h), events: events}
}

// open starts a stream authenticated as deviceID with serial and returns it
// once the hub has welcomed it and recorded one heartbeat.
func (f *revokeFixture) open(ctx context.Context, t *testing.T, deviceID, serial string) *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage] {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(withDeviceID(r.Context(), deviceID), serialKey{}, serial)
		f.h.ServeHTTP(w, r.WithContext(ctx))
	}))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(tr.CloseIdleConnections)

	stream := agentv1connect.NewAgentServiceClient(&http.Client{Transport: tr}, srv.URL).Connect(ctx)
	if err := stream.Send(hello(ProtocolMajor)); err != nil {
		t.Fatalf("%s: send hello: %v", deviceID, err)
	}
	// Hang up before the server closes, so a stream the hub kept open does
	// not hold up the test.
	t.Cleanup(func() { _ = stream.CloseRequest() })
	if msg, err := stream.Receive(); err != nil || msg.GetWelcome() == nil {
		t.Fatalf("%s: want Welcome, got %v, %v", deviceID, msg, err)
	}
	return stream
}

// isRevoked reports whether err is Unauthenticated with the
// CertificateRevoked detail.
func isRevoked(err error) bool {
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeUnauthenticated {
		return false
	}
	for _, d := range ce.Details() {
		if v, err := d.Value(); err == nil {
			if _, ok := v.(*agentv1.CertificateRevoked); ok {
				return true
			}
		}
	}
	return false
}

// assertStreaming checks the hub still accepts heartbeats on stream: it ends
// the stream cleanly (EOF) only once the agent hangs up.
func assertStreaming(t *testing.T, name string, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]) {
	t.Helper()
	if err := stream.Send(heartbeat()); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("%s: send heartbeat: %v", name, err)
	}
	if err := stream.CloseRequest(); err != nil {
		t.Fatalf("%s: close request: %v", name, err)
	}
	if _, err := stream.Receive(); !errors.Is(err, io.EOF) {
		t.Errorf("%s: stream ended with %v, want EOF (still streaming)", name, err)
	}
}

func statusOf(t *testing.T, st *store.Store, id string) string {
	t.Helper()
	d, err := st.Devices().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return d.Status
}

// offlineEvents drains the events published so far and counts device.offline
// for id.
func offlineEvents(events <-chan Event, id string) int {
	n := 0
	for {
		select {
		case e := <-events:
			if e.Type == EventDeviceOffline && e.Device.ID == id {
				n++
			}
		default:
			return n
		}
	}
}

// A heartbeat on an open stream re-checks the certificate. A revocation
// written to the store by anyone (the CLI from another process, or Raft on a
// clustered leader) ends that device's stream at its next heartbeat and marks
// it offline; another device's stream is untouched. A hub that cannot vouch
// for its store (a follower, a hub catching up) never kicks.
func TestHeartbeatRecheckEndsRevokedStream(t *testing.T) {
	t.Parallel()
	notLeader := func() error { return notLeaderError(follower()) }
	catchingUp := func() error {
		return connect.NewError(connect.CodeUnavailable, errors.New("this hub is taking over as the cluster leader; retry shortly"))
	}
	tests := []struct {
		name       string
		replicated bool
		authority  func() error
		serial     string // dev-1's certificate on the stream
		revoke     bool
		wantEnd    func(error) bool // nil: the stream continues
	}{
		{name: "standalone revoked", serial: "0a", revoke: true, wantEnd: isRevoked},
		{name: "clustered leader revoked", replicated: true, serial: "0a", revoke: true, wantEnd: isRevoked},
		{name: "unknown certificate", serial: "ff", wantEnd: func(err error) bool {
			return connect.CodeOf(err) == connect.CodeUnauthenticated && !isRevoked(err)
		}},
		{name: "follower keeps the stream", replicated: true, authority: notLeader, serial: "0a", revoke: true},
		{name: "catching up keeps the stream", replicated: true, authority: catchingUp, serial: "0a", revoke: true},
		{name: "not revoked", serial: "0a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			f := newRevokeFixture(t, tt.replicated, tt.authority)
			dev1 := f.open(ctx, t, "dev-1", tt.serial)
			dev2 := f.open(ctx, t, "dev-2", "0b")
			if tt.revoke {
				if _, err := f.st.Certs().RevokeDevice(ctx, "dev-1", time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if got := statusOf(t, f.st, "dev-1"); got != store.StatusOnline {
				t.Fatalf("dev-1 status before the heartbeat = %s, want online", got)
			}

			if tt.wantEnd == nil {
				assertStreaming(t, "dev-1", dev1)
				if got := statusOf(t, f.st, "dev-1"); got != store.StatusOnline {
					t.Errorf("dev-1 status = %s, want online", got)
				}
			} else {
				if err := dev1.Send(heartbeat()); err != nil && !errors.Is(err, io.EOF) {
					t.Fatalf("send heartbeat: %v", err)
				}
				ended := make(chan error, 1)
				go func() {
					_, err := dev1.Receive()
					ended <- err
				}()
				var err error
				select {
				case err = <-ended:
				case <-time.After(3 * time.Second):
					_ = dev1.CloseRequest()
					t.Fatal("dev-1 stream still open after a heartbeat with a revoked certificate")
				}
				if !tt.wantEnd(err) {
					t.Fatalf("dev-1 stream ended with %v", err)
				}
				if got := statusOf(t, f.st, "dev-1"); got != store.StatusOffline {
					t.Errorf("dev-1 status = %s, want offline", got)
				}
				if n := offlineEvents(f.events, "dev-1"); n != 1 {
					t.Errorf("device.offline events for dev-1 = %d, want 1", n)
				}
				if tt.replicated {
					f.reg.liveMu.Lock()
					_, seen := f.reg.seen["dev-1"]
					f.reg.liveMu.Unlock()
					if seen {
						t.Error("dev-1 still in the leader's presence memory")
					}
				}
			}
			assertStreaming(t, "dev-2", dev2)
			if got := statusOf(t, f.st, "dev-2"); got != store.StatusOnline {
				t.Errorf("dev-2 status = %s, want online", got)
			}
		})
	}
}
