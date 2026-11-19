// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	// 1: answers ExecRequest; 2: reports its capability ceiling; 3: answers ProbeRequest; 4: sends MetricsBatch; 5: streams logs (LogRequest); 6: answers ShellRequest
	ProtocolMinor = 6
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
	// MetricsInterval is how often host metrics are sent; 0 means every 15 s.
	MetricsInterval time.Duration
	// Ceiling is what the hub may run on this device; the zero value allows
	// nothing.
	Ceiling Ceiling
	// Connected, if set, is called each time a hub accepts this agent.
	Connected func()
	// Failed, if set, is called after each attempt that no hub accepted.
	Failed func()
}

type runner struct {
	cfg           Config
	factsInterval time.Duration
	log           *slog.Logger
	id            *identity
	httpClient    *http.Client
	boot          time.Time
	// metrics samples host metrics every metricsInterval; it keeps its
	// previous readings across sessions.
	metrics         *collector
	metricsInterval time.Duration
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
	tr := newTransport(id)
	defer func() { tr.CloseIdleConnections() }()

	log := cfg.Log.With("device_id", id.deviceID)
	r := &runner{
		cfg:           cfg,
		factsInterval: cmp.Or(cfg.FactsInterval, defaultFactsInterval),
		log:           log,
		id:            id,
		httpClient:    &http.Client{Transport: tr},
		boot:          bootTime(ctx, cfg.Log),
		hubs:          id.hubs,

		metrics:         newCollector(log),
		metricsInterval: cmp.Or(cfg.MetricsInterval, defaultMetricsInterval),
	}
	log.InfoContext(ctx, "agent starting", "version", cfg.Version, "hubs", r.hubs)

	b := newBackoff()
	failed := 0 // attempts that failed in a row since the last wait or session
	for {
		hub := r.hubs[r.cur]
		started := time.Now()
		welcomed, err := r.session(ctx, hub)
		tr.CloseIdleConnections()
		if errors.Is(err, errRenewed) {
			// The hub CA rotation renewed the certificate: reconnect with it.
			if id, err := loadIdentity(cfg.DataDir); err != nil {
				log.ErrorContext(ctx, "load the renewed identity", "err", err)
			} else {
				tr = newTransport(id)
				r.id, r.httpClient = id, &http.Client{Transport: tr}
				log.InfoContext(ctx, "reconnecting with the certificate renewed for the hub CA rotation")
				continue
			}
		}
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
			if cfg.Failed != nil {
				cfg.Failed()
			}
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
	if renewed, err := r.saveRenewal(welcome); err != nil {
		r.log.ErrorContext(ctx, "save the certificate renewed for the hub CA rotation", "err", err)
	} else if renewed {
		_ = stream.CloseRequest()
		return true, errRenewed
	}
	if r.cfg.Connected != nil {
		r.cfg.Connected()
	}

	g, gctx := errgroup.WithContext(ctx)
	received := make(chan struct{})
	results := make(chan *agentv1.AgentMessage)
	g.Go(func() error {
		defer close(received)
		// Log streams run until canceled: end them as soon as receive returns.
		rctx, cancel := context.WithCancel(gctx)
		var logs *logStreams // made on the first LogRequest: most sessions never stream logs
		defer func() {
			if logs != nil {
				logs.wait()
			}
		}()
		var execs sync.WaitGroup
		defer execs.Wait()
		defer cancel()
		return r.receive(rctx, stream, &execs, &logs, results)
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

// receive consumes hub messages until the stream fails. Each exec or probe
// request runs on its own goroutine in execs, within the capability
// ceiling, and its result goes to results for sendLoop to send.
func (r *runner) receive(ctx context.Context, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
	execs *sync.WaitGroup, logs **logStreams, results chan<- *agentv1.AgentMessage,
) error {
	// Once the stream failed nothing can be sent: replies are dropped, so
	// the goroutines in execs end without waiting for ctx.
	gone := make(chan struct{})
	defer close(gone)
	send := func(ctx context.Context, msg *agentv1.AgentMessage) bool {
		select {
		case results <- msg:
			return true
		case <-ctx.Done():
			return false
		case <-gone:
			return false
		}
	}
	reply := func(msg *agentv1.AgentMessage) { send(ctx, msg) }
	// Every shell of the stream ends with it.
	shells := newShellHost(r.cfg.Ceiling, r.log, execs, reply)
	defer shells.closeAll()
	for {
		msg, err := stream.Receive()
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}
		switch p := msg.GetPayload().(type) {
		case *agentv1.HubMessage_ExecRequest:
			req := p.ExecRequest
			execs.Go(func() {
				res := r.cfg.Ceiling.execute(ctx, req)
				// Never log the arguments: they may carry secrets.
				r.log.InfoContext(ctx, "exec request", "id", req.GetId(), "action", fmt.Sprintf("%T", req.GetAction()),
					"denied", res.GetDenied(), "exit_code", res.GetExitCode())
				reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ExecResult{ExecResult: res}})
			})
		case *agentv1.HubMessage_ProbeRequest:
			req := p.ProbeRequest
			execs.Go(func() {
				res := r.cfg.Ceiling.probe(ctx, req)
				// Never log the target: a URL may carry credentials.
				r.log.DebugContext(ctx, "probe request", "id", req.GetId(), "probe", fmt.Sprintf("%T", req.GetProbe()),
					"denied", res.GetDenied(), "failed", res.GetError() != "")
				reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ProbeResult{ProbeResult: res}})
			})
		case *agentv1.HubMessage_LogRequest:
			req := p.LogRequest
			if *logs == nil {
				*logs = newLogStreams(r.cfg.Ceiling, r.log)
			}
			l := *logs
			execs.Go(func() { l.stream(ctx, req, send) })
		case *agentv1.HubMessage_LogCancel:
			if *logs != nil {
				(*logs).cancel(p.LogCancel.GetId())
			}
		case *agentv1.HubMessage_ShellRequest:
			shells.handle(ctx, p.ShellRequest)
		default:
			// Ping needs no answer: any traffic keeps the stream alive.
			r.log.DebugContext(ctx, "hub message ignored", "type", fmt.Sprintf("%T", msg.GetPayload()))
		}
	}
}

// sendLoop sends heartbeats, periodic facts and metrics, and exec and probe results until ctx is
// canceled or a send fails. It is the only sender after Hello.
func (r *runner) sendLoop(ctx context.Context, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
	interval time.Duration, results <-chan *agentv1.AgentMessage,
) error {
	hb := time.NewTicker(interval)
	defer hb.Stop()
	facts := time.NewTicker(r.factsInterval)
	defer facts.Stop()
	metrics := time.NewTicker(r.metricsInterval)
	defer metrics.Stop()
	for {
		var msg *agentv1.AgentMessage
		select {
		case <-ctx.Done():
			return nil
		case now := <-hb.C:
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: r.heartbeat(now)}}
		case <-facts.C:
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Facts{Facts: r.hello(ctx)}}
		case now := <-metrics.C:
			samples := r.metrics.collect(ctx, now)
			if len(samples) == 0 {
				continue
			}
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_MetricsBatch{MetricsBatch: &agentv1.MetricsBatch{Samples: samples}}}
		case msg = <-results:
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
