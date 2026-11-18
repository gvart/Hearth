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
	"net/url"
	"path/filepath"
	"slices"
	"sync"
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
	ProtocolMinor = 2 // 1: answers ExecRequest; 2: reports its capability ceiling
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
	// stableSession is how long a session must have lasted for its end to
	// earn a quick reconnect. A hub that welcomes and then drops the agent
	// at once gets the normal backoff instead of a fast loop.
	stableSession = time.Second
)

// Config holds what Run needs.
type Config struct {
	DataDir string       // holds the identity written by Join
	Version string       // reported to the hub as agent_version
	Log     *slog.Logger // required
	// FactsInterval is how often host facts are re-sent; 0 means every 10 min.
	FactsInterval time.Duration
	// Ceiling is what the hub may run on this device; the zero value allows
	// nothing.
	Ceiling Ceiling
}

type runner struct {
	cfg           Config
	factsInterval time.Duration
	log           *slog.Logger
	id            *identity
	httpClient    *http.Client
	boot          time.Time
	// hubs are the hubs to try, in order, and cur the index of the next one.
	// Only Run's goroutine touches them.
	hubs []string
	cur  int
}

// ErrRevoked is returned by Run when a hub that can vouch for it says this
// device's certificate is revoked. Retrying cannot help: the device must
// re-enroll. `hearth agent run` exits with ExitRevoked on it.
var ErrRevoked = errors.New("this device's certificate was revoked; re-enroll with hearth agent join")

// ExitRevoked is the exit status of `hearth agent run` on ErrRevoked
// (EX_CONFIG from sysexits.h). The systemd unit lists it in
// RestartPreventExitStatus=, so a revoked agent stays stopped.
const ExitRevoked = 78

// Run keeps the agent connected to the cluster leader until ctx is canceled:
// it loads the identity from cfg.DataDir, opens the mTLS stream, sends Hello
// with host facts, then heartbeats at the interval the hub asks for.
//
// The agent knows every hub: the join URL plus the list each Welcome carries,
// kept in HubsFile. A failed attempt moves on to the next hub at once; only
// when every hub failed in a row does the agent wait, with exponential
// backoff. A follower's NotLeader refusal sends it straight to the leader it
// names. When an established session ends, the first retry goes to the same
// hub almost at once, as it is likely restarting. Run only returns early when
// the data dir holds no usable identity, or with ErrRevoked once a hub says
// the certificate is revoked; a NotLeader or Unavailable answer never stops
// it. Cancellation returns nil.
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

	log := cfg.Log.With("device_id", id.deviceID)
	r := &runner{
		cfg:           cfg,
		factsInterval: cmp.Or(cfg.FactsInterval, defaultFactsInterval),
		log:           log,
		id:            id,
		httpClient:    &http.Client{Transport: tr},
		boot:          bootTime(ctx, cfg.Log),
		hubs:          id.hubs,
	}
	log.InfoContext(ctx, "agent starting", "version", cfg.Version, "hubs", r.hubs)

	b := newBackoff()
	failed := 0 // attempts that failed in a row since the last wait or session
	for {
		hub := r.hubs[r.cur]
		started := time.Now()
		welcomed, err := r.session(ctx, hub)
		tr.CloseIdleConnections()
		if ctx.Err() != nil {
			log.InfoContext(ctx, "agent stopped")
			return nil
		}
		if revoked(err) {
			// Join refuses a data dir that holds an identity; say what to remove.
			cert := filepath.Join(cfg.DataDir, CertFile)
			log.ErrorContext(ctx, ErrRevoked.Error(), "hub", hostOf(hub), "remove_before_join", cert)
			return fmt.Errorf("%w (remove %s first)", ErrRevoked, cert)
		}
		leader := r.redirect(ctx, hub, err)
		if welcomed {
			// Retry the same hub first: it most likely restarted.
			b.reset(time.Since(started) >= stableSession)
			failed = 0
		} else {
			failed++
			r.cur = (r.cur + 1) % len(r.hubs)
		}
		if leader >= 0 {
			r.cur = leader
		}
		if !welcomed && failed < len(r.hubs) {
			log.WarnContext(ctx, "hub unavailable; trying the next hub", "hub", hostOf(hub), "err", err, "next", hostOf(r.hubs[r.cur]))
			continue
		}
		failed = 0
		d := b.next()
		log.WarnContext(ctx, "hub connection lost; reconnecting", "hub", hostOf(hub), "err", err, "retry_in", d.Round(time.Millisecond))
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

// redirect handles a follower's NotLeader refusal from hub: it adds the
// leader and the hubs it names to the list and returns the leader's index, or
// -1 if err is no such refusal or names no other hub.
func (r *runner) redirect(ctx context.Context, hub string, err error) int {
	nl := notLeader(err)
	if nl == nil {
		return -1
	}
	r.hubs = mergeHubs(r.hubs, []string{nl.GetLeaderUrl()}, nl.GetHubs())
	leader := mergeHubs([]string{nl.GetLeaderUrl()})
	if len(leader) == 0 || leader[0] == hub {
		r.log.WarnContext(ctx, "hub is not the leader and knows no leader", "hub", hostOf(hub))
		return -1
	}
	r.log.InfoContext(ctx, "hub is not the leader; redirecting", "hub", hostOf(hub), "leader", hostOf(leader[0]))
	return slices.Index(r.hubs, leader[0])
}

// revoked reports whether err is a hub's refusal carrying the
// CertificateRevoked detail. Only that detail counts: a bare Unauthenticated
// (say, an unknown certificate) or a NotLeader or Unavailable answer from a
// hub that cannot vouch for its store is retried as usual.
func revoked(err error) bool {
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeUnauthenticated {
		return false
	}
	for _, d := range cerr.Details() {
		if v, err := d.Value(); err == nil {
			if _, ok := v.(*agentv1.CertificateRevoked); ok {
				return true
			}
		}
	}
	return false
}

// learnHubs makes the hubs a Welcome from hub listed the new hub list: hub
// first, so a reconnect tries it first, then the listed hubs, then the join
// URL, which is always kept. An empty list (a hub that does not know its
// URL) changes nothing. A changed list is saved to HubsFile.
func (r *runner) learnHubs(ctx context.Context, hub string, listed []string) {
	if len(listed) == 0 {
		return
	}
	hubs := mergeHubs([]string{hub}, listed, []string{r.id.hubURL.String()})
	if slices.Equal(hubs, r.hubs) {
		return
	}
	r.hubs, r.cur = hubs, 0
	r.log.InfoContext(ctx, "hub list updated", "hubs", hubs)
	if err := writeHubs(r.cfg.DataDir, hubs); err != nil {
		// Not fatal: the list in memory works, and the next Welcome retries.
		r.log.WarnContext(ctx, "save hub list", "err", err)
	}
}

// hostOf is the host:port of a hub URL, for logs.
func hostOf(hub string) string {
	if u, err := url.Parse(hub); err == nil {
		return u.Host
	}
	return hub
}

// session runs one stream to hub until it fails or ctx is canceled.
// welcomed reports whether the hub accepted the Hello.
//
// The stream does not use ctx directly: on shutdown the agent half-closes it
// so the hub sees a clean end, and only aborts it if the hub does not finish
// within closeGrace. Cancelling alone is not enough either way: a Receive
// blocked on the hub only notices once the request side is closed.
func (r *runner) session(ctx context.Context, hub string) (welcomed bool, err error) {
	streamCtx, abort := context.WithCancel(context.WithoutCancel(ctx))
	defer abort()
	stream := agentv1connect.NewAgentServiceClient(r.httpClient, hub).Connect(streamCtx)
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
	r.log.InfoContext(ctx, "connected to hub", "hub", hostOf(hub), "heartbeat_interval", interval)
	r.learnHubs(ctx, hub, welcome.GetHubs())

	g, gctx := errgroup.WithContext(ctx)
	received := make(chan struct{})
	results := make(chan *agentv1.ExecResult)
	g.Go(func() error {
		defer close(received)
		var execs sync.WaitGroup
		defer execs.Wait()
		return r.receive(gctx, stream, &execs, results)
	})
	g.Go(func() error {
		err := r.sendLoop(gctx, stream, interval, results)
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
	h.Ceiling = r.cfg.Ceiling.proto()
	return h
}

// receive consumes hub messages until the stream fails. Each exec request
// runs on its own goroutine in execs, within the capability ceiling, and
// its result goes to results for sendLoop to send.
func (r *runner) receive(ctx context.Context, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
	execs *sync.WaitGroup, results chan<- *agentv1.ExecResult,
) error {
	for {
		msg, err := stream.Receive()
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}
		req := msg.GetExecRequest()
		if req == nil {
			// Ping needs no answer: any traffic keeps the stream alive.
			r.log.DebugContext(ctx, "hub message ignored", "type", fmt.Sprintf("%T", msg.GetPayload()))
			continue
		}
		execs.Go(func() {
			res := r.cfg.Ceiling.execute(ctx, req)
			// Never log the arguments: they may carry secrets.
			r.log.InfoContext(ctx, "exec request", "id", req.GetId(), "action", fmt.Sprintf("%T", req.GetAction()),
				"denied", res.GetDenied(), "exit_code", res.GetExitCode())
			select {
			case results <- res:
			case <-ctx.Done():
			}
		})
	}
}

// sendLoop sends heartbeats, periodic facts and exec results until ctx is canceled or a
// send fails. It is the only sender after Hello.
func (r *runner) sendLoop(ctx context.Context, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
	interval time.Duration, results <-chan *agentv1.ExecResult,
) error {
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
		case res := <-results:
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ExecResult{ExecResult: res}}
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
