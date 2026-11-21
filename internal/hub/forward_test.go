// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// fakeMasters is master "b" of a cluster whose master "a" serves at srv.
type fakeMasters struct {
	live map[string]bool
	srv  *url.URL
}

func (f fakeMasters) Self() string          { return "b" }
func (f fakeMasters) Live(id string) bool   { return f.live[id] }
func (f fakeMasters) OwnerOf(string) string { return "a" }
func (f fakeMasters) AgentURLOf(_ context.Context, id string) string {
	return "https://" + id + ".lan:8443"
}

func (f fakeMasters) Client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !f.live[r.URL.Host] {
			return nil, errors.New("unreachable")
		}
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = f.srv.Scheme, f.srv.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestForwardedExecReachesTheOwningMaster: master b has no stream for
// dev-1; its route names master a, which holds it, so b's exec runs on a's
// stream. A route to a master that is down or not live is a clear error.
func TestForwardedExecReachesTheOwningMaster(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, onA := newExecClient(t, st)
	stream := connectAgent(ctx, t, client, 2, &agentv1.Ceiling{Exec: []string{"/bin/true"}})
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ExecResult{
				ExecResult: &agentv1.ExecResult{Id: msg.GetExecRequest().GetId(), ExitCode: 7},
			}})
		}
	}()
	for range 100 { // the session attaches just after Welcome
		if onA.Local("dev-1") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv := httptest.NewServer(AgentsHandler(onA, nil, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	routes := st.DeviceRoutes()
	if err := routes.Set(ctx, "dev-1", "a", time.Now()); err != nil {
		t.Fatal(err)
	}

	onB := NewAgents(st.Devices())
	if _, err := onB.Exec(ctx, "dev-1", trueCmd()); !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("Exec without masters = %v, want ErrAgentNotConnected", err)
	}
	live := map[string]bool{"a": true, "b": true}
	onB.SetMasters(fakeMasters{live: live, srv: u}, routes)
	if err := onB.Check(ctx, "dev-1-name", trueCmd()); err != nil {
		t.Fatalf("forwarded Check = %v", err)
	}
	res, err := onB.Exec(ctx, "dev-1-name", trueCmd())
	if err != nil || res.GetExitCode() != 7 {
		t.Fatalf("forwarded Exec = %v, %v; want the agent's result from master a", res, err)
	}
	// Beyond the agent's ceiling: refused on a, with the kind kept.
	if _, err := onB.Exec(ctx, "dev-1", &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{Argv: []string{"/bin/rm"}}}}); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Fatalf("forwarded Exec beyond the ceiling = %v, want ErrBeyondCeiling", err)
	}

	// a went down: the error says so and is still "not connected".
	srv.Close()
	if _, err := onB.Exec(ctx, "dev-1", trueCmd()); !errors.Is(err, ErrStreamElsewhere) || !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("Exec with master a down = %v, want ErrStreamElsewhere", err)
	}
	// a dies while it runs the request: the command may have run.
	dying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(dying.Close)
	du, _ := url.Parse(dying.URL)
	onB.SetMasters(fakeMasters{live: live, srv: du}, routes)
	if _, err := onB.Exec(ctx, "dev-1", trueCmd()); !errors.Is(err, automation.ErrOutcomeUnknown) {
		t.Fatalf("Exec with master a dying mid-call = %v, want ErrOutcomeUnknown", err)
	}
	if err := onB.Check(ctx, "dev-1", trueCmd()); !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("Check with master a dying mid-call = %v, want ErrAgentNotConnected", err)
	}
	// a left the cluster: nothing to forward to.
	live["a"] = false
	if _, err := onB.Exec(ctx, "dev-1", trueCmd()); errors.Is(err, ErrStreamElsewhere) || !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("Exec with master a gone = %v, want only ErrAgentNotConnected", err)
	}
}

// TestPresenceOwner: the stream holder owns a device's presence; with no
// live holder, the ring owner does, after the grace.
func TestPresenceOwner(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	st := newTestStore(t)
	routes := st.DeviceRoutes()
	now := time.Unix(1000, 0)
	ring := &fakeRing{self: "b", live: map[string]bool{"a": true, "b": true}, owns: true, since: now.Add(-time.Minute)}
	owns := PresenceOwner(NewAgents(st.Devices()), routes, ring, 30*time.Second, func() time.Time { return now })
	dev := store.Device{ID: "dev-1"}

	if !owns(ctx, dev) {
		t.Error("ring owner with no route: not the owner")
	}
	if err := routes.Set(ctx, "dev-1", "a", now); err != nil {
		t.Fatal(err)
	}
	if owns(ctx, dev) {
		t.Error("owner while live master a holds the stream")
	}
	ring.live["a"] = false
	if !owns(ctx, dev) {
		t.Error("ring owner after the holder died: not the owner")
	}
	ring.since = now.Add(-29 * time.Second)
	if owns(ctx, dev) {
		t.Error("owner within the grace after the masters changed")
	}
	ring.owns = false
	ring.since = now.Add(-time.Hour)
	if owns(ctx, dev) {
		t.Error("owner of a device another master owns on the ring")
	}
	if err := routes.Set(ctx, "dev-1", "b", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !owns(ctx, dev) {
		t.Error("route names this master: not the owner")
	}
}

type fakeRing struct {
	self  string
	live  map[string]bool
	owns  bool
	since time.Time
}

func (r *fakeRing) Self() string        { return r.self }
func (r *fakeRing) Live(id string) bool { return r.live[id] }
func (r *fakeRing) Owns(string) bool    { return r.owns }
func (r *fakeRing) Since() time.Time    { return r.since }
