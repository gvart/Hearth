// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
)

// Protocol version this agent speaks.
const (
	ProtocolMajor = 1
	ProtocolMinor = 0
)

const (
	// defaultHeartbeatInterval applies when Welcome does not set one.
	defaultHeartbeatInterval = 10 * time.Second
	// minHeartbeatInterval keeps a misconfigured hub from making the agent spin.
	minHeartbeatInterval = time.Second
	// defaultFactsInterval is how often host facts are re-sent during a session.
	defaultFactsInterval = 10 * time.Minute
	// closeGrace is how long a closing stream waits for the hub to finish.
	closeGrace = 2 * time.Second
)

// Config holds what Run needs.
type Config struct {
	DataDir string       // holds the identity written by Join
	Version string       // reported to the hub as agent_version
	Log     *slog.Logger // required
	// FactsInterval is how often host facts are re-sent; 0 means every 10 min.
	FactsInterval time.Duration
}

type runner struct {
	cfg           Config
	factsInterval time.Duration
	log           *slog.Logger
	id            *identity
	client        agentv1connect.AgentServiceClient
	boot          time.Time
}

// Run keeps the agent connected to its hub until ctx is canceled: it loads the
// identity from cfg.DataDir, opens the mTLS stream, sends Hello with host facts,
// then heartbeats at the interval the hub asks for. Lost or refused connections
// are retried with exponential backoff; Run only returns early when the data
// dir holds no usable identity. Cancellation returns nil.
func Run(ctx context.Context, cfg Config) error {
	id, err := loadIdentity(cfg.DataDir)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     id.tls,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
		// The hub sends nothing between messages; pings detect a dead peer.
		HTTP2: &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
	}
	defer tr.CloseIdleConnections()

	log := cfg.Log.With("hub", id.hubURL.Host, "device_id", id.deviceID)
	r := &runner{
		cfg:           cfg,
		factsInterval: cmp.Or(cfg.FactsInterval, defaultFactsInterval),
		log:           log,
		id:            id,
		client:        agentv1connect.NewAgentServiceClient(&http.Client{Transport: tr}, id.hubURL.String()),
		boot:          bootTime(ctx, cfg.Log),
	}
	log.InfoContext(ctx, "agent starting", "version", cfg.Version)

	b := newBackoff()
	for {
		welcomed, err := r.session(ctx)
		tr.CloseIdleConnections()
		if ctx.Err() != nil {
			log.InfoContext(ctx, "agent stopped")
			return nil
		}
		if welcomed {
			b.reset()
		}
		d := b.next()
		log.WarnContext(ctx, "hub connection lost; reconnecting", "err", err, "retry_in", d.Round(time.Millisecond))
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			log.InfoContext(ctx, "agent stopped")
			return nil
		case <-t.C:
		}
	}
}

// session runs one stream to the hub until it fails or ctx is canceled.
// welcomed reports whether the hub accepted the Hello.
//
// The stream does not use ctx directly: on shutdown the agent half-closes it
// so the hub sees a clean end, and only aborts it if the hub does not finish
// within closeGrace. Cancelling alone is not enough either way: a Receive
// blocked on the hub only notices once the request side is closed.
func (r *runner) session(ctx context.Context) (welcomed bool, err error) {
	streamCtx, abort := context.WithCancel(context.WithoutCancel(ctx))
	defer abort()
	stream := r.client.Connect(streamCtx)
	defer func() { _ = stream.CloseResponse() }()

	hello := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: r.hello(ctx)}}
	unwatch := context.AfterFunc(ctx, abort)
	err = stream.Send(hello)
	if !unwatch() {
		return false, ctx.Err()
	}
	// On a failed stream Send returns io.EOF and Receive carries the cause.
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("send hello: %w", err)
	}
	unwatch = context.AfterFunc(ctx, func() { _ = stream.CloseRequest(); abort() })
	first, err := stream.Receive()
	if !unwatch() {
		return false, ctx.Err()
	}
	if err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	welcome := first.GetWelcome()
	if welcome == nil {
		return false, errors.New("connect: hub did not answer Hello with Welcome")
	}
	interval := heartbeatInterval(welcome.GetHeartbeatInterval())
	r.log.InfoContext(ctx, "connected to hub", "heartbeat_interval", interval)

	g, gctx := errgroup.WithContext(ctx)
	received := make(chan struct{})
	g.Go(func() error {
		defer close(received)
		return r.receive(gctx, stream)
	})
	g.Go(func() error {
		err := r.sendLoop(gctx, stream, interval)
		_ = stream.CloseRequest()
		t := time.NewTimer(closeGrace)
		defer t.Stop()
		select {
		case <-received:
		case <-t.C:
			abort()
		}
		return err
	})
	return true, g.Wait()
}

// heartbeatInterval is the interval from Welcome, or the default when unset,
// never below minHeartbeatInterval.
func heartbeatInterval(d *durationpb.Duration) time.Duration {
	if d == nil {
		return defaultHeartbeatInterval
	}
	return max(d.AsDuration(), minHeartbeatInterval)
}

// hello is the first message of a session: the device and its facts.
func (r *runner) hello(ctx context.Context) *agentv1.Hello {
	h := collectFacts(ctx, r.log)
	h.ProtocolVersion = &agentv1.ProtocolVersion{Major: ProtocolMajor, Minor: ProtocolMinor}
	h.DeviceId = r.id.deviceID // informational; the hub uses the certificate
	h.AgentVersion = r.cfg.Version
	return h
}

// receive consumes hub messages until the stream fails.
func (r *runner) receive(ctx context.Context, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]) error {
	for {
		msg, err := stream.Receive()
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}
		// Ping needs no answer: any traffic keeps the stream alive. Exec
		// requests are not supported yet and are never run.
		r.log.DebugContext(ctx, "hub message ignored", "type", fmt.Sprintf("%T", msg.GetPayload()))
	}
}

// sendLoop sends heartbeats and periodic facts until ctx is canceled or a
// send fails. It is the only sender after Hello.
func (r *runner) sendLoop(ctx context.Context, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage], interval time.Duration) error {
	hb := time.NewTicker(interval)
	defer hb.Stop()
	facts := time.NewTicker(r.factsInterval)
	defer facts.Stop()
	for {
		var msg *agentv1.AgentMessage
		select {
		case <-ctx.Done():
			return nil
		case now := <-hb.C:
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: r.heartbeat(now)}}
		case <-facts.C:
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Facts{Facts: r.hello(ctx)}}
		}
		if err := stream.Send(msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil // the stream is gone; receive reports why
			}
			return fmt.Errorf("send: %w", err)
		}
	}
}

func (r *runner) heartbeat(now time.Time) *agentv1.Heartbeat {
	hb := &agentv1.Heartbeat{Ts: timestamppb.New(now)}
	if !r.boot.IsZero() {
		hb.Uptime = durationpb.New(now.Sub(r.boot))
	}
	return hb
}
