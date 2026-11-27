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
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// newTestClient serves AgentStream over unencrypted HTTP/2 (bidi streaming needs h2)
// and returns a client for it. Every request is authenticated as deviceID, standing
// in for requireClientCert; an empty deviceID leaves requests unauthenticated.
func newTestClient(t *testing.T, deviceID string) agentv1connect.AgentServiceClient {
	t.Helper()
	c, _ := newStreamClient(t, deviceID, nil)
	return c
}

// newStreamClient is newTestClient with the hub's Leadership set to lead
// (nil keeps the single-hub default). It also returns the hub's store, in
// which dev-1 is enrolled.
func newStreamClient(t *testing.T, deviceID string, lead Leadership) (agentv1connect.AgentServiceClient, *store.Store) {
	t.Helper()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	reg := NewRegistry(RegistryConfig{Store: st})
	as := NewAgentStream(slog.New(slog.DiscardHandler), 5*time.Second, reg)
	if lead != nil {
		as.leadership = lead
	}
	path, h := agentv1connect.NewAgentServiceHandler(as)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deviceID != "" {
			r = r.WithContext(withDeviceID(r.Context(), deviceID))
		}
		h.ServeHTTP(w, r)
	}))

	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)

	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(transport.CloseIdleConnections)
	return agentv1connect.NewAgentServiceClient(&http.Client{Transport: transport}, srv.URL), st
}

func hello(major uint32) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ProtocolVersion: &agentv1.ProtocolVersion{Major: major},
		DeviceId:        "dev-1",
		Hostname:        "pi",
		Os:              "linux",
		Arch:            "arm64",
		CpuCores:        4,
		Interfaces:      []*agentv1.NetworkInterface{{Name: "eth0", Mac: "aa:bb:cc:dd:ee:ff", Ips: []string{"10.0.0.2"}}},
		AgentVersion:    "v0.0.0-test",
	}}}
}

func heartbeat() *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
		Ts:     timestamppb.Now(),
		Uptime: durationpb.New(time.Minute),
	}}}
}

func TestConnectRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	stream := newTestClient(t, "dev-1").Connect(ctx)
	if err := stream.Send(hello(ProtocolMajor)); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	for i := range 3 {
		if err := stream.Send(heartbeat()); err != nil {
			t.Fatalf("send heartbeat %d: %v", i, err)
		}
	}
	// A periodic facts message is accepted, unlike a second Hello.
	facts := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Facts{Facts: hello(ProtocolMajor).GetHello()}}
	if err := stream.Send(facts); err != nil {
		t.Fatalf("send facts: %v", err)
	}

	msg, err := stream.Receive()
	if err != nil {
		t.Fatalf("receive welcome: %v", err)
	}
	welcome := msg.GetWelcome()
	if welcome == nil {
		t.Fatalf("got %T, want Welcome", msg.GetPayload())
	}
	if got := welcome.GetHeartbeatInterval().AsDuration(); got != 5*time.Second {
		t.Errorf("heartbeat_interval = %v, want 5s", got)
	}
	if welcome.GetServerTime() == nil {
		t.Error("server_time not set")
	}

	if err := stream.CloseRequest(); err != nil {
		t.Fatalf("close request: %v", err)
	}
	if _, err := stream.Receive(); !errors.Is(err, io.EOF) {
		t.Fatalf("after close: got %v, want EOF (hub accepted all heartbeats)", err)
	}
}

func TestConnectRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		first *agentv1.AgentMessage
		want  connect.Code
	}{
		{"unknown major version", hello(ProtocolMajor + 1), connect.CodeFailedPrecondition},
		{"zero major version", hello(0), connect.CodeFailedPrecondition},
		{"heartbeat before hello", heartbeat(), connect.CodeInvalidArgument},
		{"empty message", &agentv1.AgentMessage{}, connect.CodeInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			stream := newTestClient(t, "dev-1").Connect(ctx)
			// The hub may refuse and close the stream before the send
			// completes; Connect then reports io.EOF on Send and the real
			// error on Receive.
			if err := stream.Send(tt.first); err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("send: %v", err)
			}
			_, err := stream.Receive()
			if got := connect.CodeOf(err); got != tt.want {
				t.Fatalf("code = %v (%v), want %v", got, err, tt.want)
			}
		})
	}
}

func TestConnectDuplicateHello(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	stream := newTestClient(t, "dev-1").Connect(ctx)
	for range 2 {
		if err := stream.Send(hello(ProtocolMajor)); err != nil {
			t.Fatalf("send hello: %v", err)
		}
	}
	if msg, err := stream.Receive(); err != nil || msg.GetWelcome() == nil {
		t.Fatalf("first receive: msg=%v err=%v, want Welcome", msg, err)
	}
	if _, err := stream.Receive(); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", err)
	}
}

func TestConnectRequiresIdentity(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	stream := newTestClient(t, "").Connect(ctx)
	_ = stream.Send(hello(ProtocolMajor))
	if _, err := stream.Receive(); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("got %v, want Unauthenticated", err)
	}
}
