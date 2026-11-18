// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// newExecClient serves an AgentStream for dev-1 and returns a client and the
// stream's Agents.
func newExecClient(t *testing.T, st *store.Store) (agentv1connect.AgentServiceClient, *Agents) {
	t.Helper()
	as := NewAgentStream(slog.New(slog.DiscardHandler), 5*time.Second, NewRegistry(RegistryConfig{Store: st}))
	path, h := agentv1connect.NewAgentServiceHandler(as)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(withDeviceID(r.Context(), "dev-1")))
	}))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(transport.CloseIdleConnections)
	return agentv1connect.NewAgentServiceClient(&http.Client{Transport: transport}, srv.URL), as.agents
}

// connectAgent opens a stream for dev-1 speaking protocol minor and reads
// the Welcome.
func connectAgent(ctx context.Context, t *testing.T, c agentv1connect.AgentServiceClient, minor uint32) *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage] {
	t.Helper()
	stream := c.Connect(ctx)
	t.Cleanup(func() {
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
	})
	h := hello(ProtocolMajor)
	h.GetHello().ProtocolVersion.Minor = minor
	if err := stream.Send(h); err != nil {
		t.Fatal(err)
	}
	if msg, err := stream.Receive(); err != nil || msg.GetWelcome() == nil {
		t.Fatalf("receive welcome: %v %v", msg, err)
	}
	return stream
}

func TestAgentsExec(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)

	if _, err := agents.Exec(ctx, "dev-1", &agentv1.ExecRequest{}); !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("Exec before connect = %v, want ErrAgentNotConnected", err)
	}

	stream := connectAgent(ctx, t, client, 1)
	// The agent answers each request with its id.
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			req := msg.GetExecRequest()
			_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ExecResult{
				ExecResult: &agentv1.ExecResult{Id: req.GetId(), Denied: true},
			}})
		}
	}()
	// By id, name and hostname.
	for _, ref := range []string{"dev-1", "dev-1-name"} {
		var res *agentv1.ExecResult
		var err error
		for range 100 { // the session attaches just after Welcome
			if res, err = agents.Exec(ctx, ref, &agentv1.ExecRequest{}); !errors.Is(err, ErrAgentNotConnected) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil || !res.GetDenied() {
			t.Errorf("Exec(%s) = %v, %v; want the agent's denial", ref, res, err)
		}
	}
	if _, err := agents.Exec(ctx, "nope", &agentv1.ExecRequest{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Exec on unknown device = %v, want ErrNotFound", err)
	}

	_ = stream.CloseRequest()
	_ = stream.CloseResponse()
	for range 100 {
		if _, err := agents.Exec(ctx, "dev-1", &agentv1.ExecRequest{}); errors.Is(err, ErrAgentNotConnected) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("agent still connected after its stream ended")
}

func TestAgentsExecOldAgent(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	connectAgent(ctx, t, client, 0)
	var err error
	for range 100 {
		if _, err = agents.Exec(ctx, "dev-1", &agentv1.ExecRequest{}); !errors.Is(err, ErrAgentNotConnected) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Errorf("Exec on a minor 0 agent = %v, want too old", err)
	}
}

func TestAgentsExecAmbiguousName(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	enrollDevice(t, st, "dev-2")
	if err := st.Devices().Upsert(t.Context(), store.Device{ID: "dev-2", Name: "dev-1-name", Status: store.StatusUnknown}); err != nil {
		t.Fatal(err)
	}
	_, err := NewAgents(st.Devices()).Exec(t.Context(), "dev-1-name", &agentv1.ExecRequest{})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("Exec by a shared name = %v, want ambiguous", err)
	}
}
