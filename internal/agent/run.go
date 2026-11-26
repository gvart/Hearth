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
	"sync/atomic"
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
	// 1: answers ExecRequest; 2: reports its capability ceiling; 3: answers ProbeRequest; 4: sends MetricsBatch; 5: streams logs (LogRequest); 6: answers ShellRequest; 7: answers ScanRequest; 8: sends NetEdges; 9: answers DockerRequest; 10: takes CeilingConfig
	ProtocolMinor = 10
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
	// NetEdgesInterval is how often network edges are sent when the ceiling
	// allows them; 0 means every minute.
	NetEdgesInterval time.Duration
	// readNetEdges, set by tests, replaces the platform's readNetEdges.
	readNetEdges func() (*agentv1.NetEdges, error)
	// Ceiling is what the agent's flags let the hub run on this device; the
	// zero value allows nothing. The hub may add to it (ceiling.go).
	Ceiling Ceiling
	// LocalCeiling makes Ceiling the whole ceiling: the agent ignores the
	// ceiling the hub sets, and a saved one (--local-ceiling).
	LocalCeiling bool
	// DockerSocket is the Docker or Podman engine's unix socket, for
	// Ceiling.Docker; empty tries DefaultDockerSocket, then Podman's.
	DockerSocket string
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
	// netEdges reads the network edges sent every netEdgesInterval, only if
	// the ceiling allows it.
	netEdges         func() (*agentv1.NetEdges, error)
	netEdgesInterval time.Duration
	// hubs are the hubs to try, in order, and cur the index of the next one.
	// Only Run's goroutine touches them.
	hubs []string
	cur  int
	// scanning is set while a network scan runs: one at a time.
	scanning atomic.Bool
	// docker reaches the container engine, for DockerRequests.
	docker dockerEngine
	// ceilings is the effective ceiling, read by every request.
	ceilings *ceilings
	// ceilingChanged wakes sendLoop to report a new ceiling at once.
	ceilingChanged chan struct{}
}

// ceiling is the effective capability ceiling.
func (r *runner) ceiling() Ceiling {
	if r.ceilings == nil { // a runner a test made
		return r.cfg.Ceiling
	}
	return r.ceilings.get()
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

		netEdges:         readNetEdges,
		netEdgesInterval: cmp.Or(cfg.NetEdgesInterval, defaultNetEdgesInterval),

		docker: dockerEngine{sockets: dockerSockets(cfg.DockerSocket)},

		ceilingChanged: make(chan struct{}, 1),
	}
	var hubCeiling Ceiling
	if !cfg.LocalCeiling {
		// A file that cannot be read leaves the flags alone: the hub sends
		// its ceiling again on connect.
		if hubCeiling, err = readCeilingFile(cfg.DataDir); err != nil {
			log.WarnContext(ctx, "ignoring the saved capability ceiling; using the flags only", "err", err)
			hubCeiling = Ceiling{}
		}
	}
	r.ceilings = newCeilings(cfg.Ceiling, hubCeiling, cfg.LocalCeiling)
	if cfg.readNetEdges != nil {
		r.netEdges = cfg.readNetEdges
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

// learnHubs makes the hubs a Welcome or Hubs message from hub listed the
// new hub list: hub first, so a reconnect tries it first, then the listed
// hubs, then the join URL, which is always kept. An empty list (a hub that does not know its
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
		return r.receive(rctx, hub, stream, &execs, &logs, results)
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
	h.Ceiling = r.ceiling().proto()
	h.LocalCeiling = r.ceilings.local.proto()
	h.CeilingLocked = r.ceilings.locked
	return h
}

// receive consumes hub messages from hub until the stream fails. Each exec
// or probe request runs on its own goroutine in execs, within the
// capability ceiling, and its result goes to results for sendLoop to send.
// A Hubs list is learned here, inline: Run reads the hub list only once the
// session is over.
func (r *runner) receive(ctx context.Context, hub string, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
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
	shells := newShellHost(r.ceiling(), r.log, execs, reply)
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
				res := r.ceiling().execute(ctx, req)
				// Never log the arguments: they may carry secrets.
				r.log.InfoContext(ctx, "exec request", "id", req.GetId(), "action", fmt.Sprintf("%T", req.GetAction()),
					"denied", res.GetDenied(), "exit_code", res.GetExitCode())
				reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ExecResult{ExecResult: res}})
			})
		case *agentv1.HubMessage_ProbeRequest:
			req := p.ProbeRequest
			execs.Go(func() {
				res := r.ceiling().probe(ctx, req)
				// Never log the target: a URL may carry credentials.
				r.log.DebugContext(ctx, "probe request", "id", req.GetId(), "probe", fmt.Sprintf("%T", req.GetProbe()),
					"denied", res.GetDenied(), "failed", res.GetError() != "")
				reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ProbeResult{ProbeResult: res}})
			})
		case *agentv1.HubMessage_LogRequest:
			req := p.LogRequest
			if *logs == nil {
				*logs = newLogStreams(r.ceiling(), r.log)
			}
			l := *logs
			execs.Go(func() { l.stream(ctx, req, send) })
		case *agentv1.HubMessage_LogCancel:
			if *logs != nil {
				(*logs).cancel(p.LogCancel.GetId())
			}
		case *agentv1.HubMessage_ShellRequest:
			shells.handle(ctx, p.ShellRequest)
		case *agentv1.HubMessage_Hubs:
			// The masters changed since the Welcome.
			r.learnHubs(ctx, hub, p.Hubs.GetUrls())
		case *agentv1.HubMessage_CeilingConfig:
			// Applied inline, so a request after it meets the new ceiling;
			// what the new one no longer allows ends now.
			if r.applyCeiling(ctx, p.CeilingConfig) {
				c := r.ceiling()
				shells.setCeiling(ctx, c)
				if *logs != nil {
					(*logs).setCeiling(ctx, c)
				}
			}
		case *agentv1.HubMessage_ScanRequest:
			req := p.ScanRequest
			execs.Go(func() {
				res := r.scan(ctx, req)
				r.log.InfoContext(ctx, "scan request", "id", req.GetId(), "subnets", req.GetSubnets(),
					"denied", res.GetDenied(), "hosts", len(res.GetHosts()), "error", res.GetError())
				reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ScanResult{ScanResult: res}})
			})
		case *agentv1.HubMessage_DockerRequest:
			req := p.DockerRequest
			execs.Go(func() {
				res := r.docker.docker(ctx, r.ceiling(), req)
				r.log.InfoContext(ctx, "docker request", "id", req.GetId(), "op", dockerOp(req),
					"denied", res.GetDenied(), "error", res.GetError())
				reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_DockerResult{DockerResult: res}})
			})
		default:
			// Ping needs no answer: any traffic keeps the stream alive.
			r.log.DebugContext(ctx, "hub message ignored", "type", fmt.Sprintf("%T", msg.GetPayload()))
		}
	}
}

// sendLoop sends heartbeats, periodic facts, metrics and network edges, and exec and probe results until ctx is
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
	// Network edges are read only when the ceiling allows them; otherwise
	// edgesC stays nil and never fires.
	var edgesC <-chan time.Time
	edges := time.NewTimer(min(netEdgesFirst, r.netEdgesInterval))
	defer edges.Stop()
	if r.ceiling().NetEdges {
		edgesC = edges.C
	}
	for {
		var msg *agentv1.AgentMessage
		select {
		case <-ctx.Done():
			return nil
		case now := <-hb.C:
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: r.heartbeat(now)}}
		case <-facts.C:
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Facts{Facts: r.hello(ctx)}}
		case <-r.ceilingChanged:
			// Report the new ceiling at once: the hub checks against it.
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Facts{Facts: r.hello(ctx)}}
			switch on := r.ceiling().NetEdges; {
			case on && edgesC == nil:
				edges.Reset(min(netEdgesFirst, r.netEdgesInterval))
				edgesC = edges.C
			case !on:
				edgesC = nil
			}
		case now := <-metrics.C:
			samples := r.metrics.collect(ctx, now)
			if len(samples) == 0 {
				continue
			}
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_MetricsBatch{MetricsBatch: &agentv1.MetricsBatch{Samples: samples}}}
		case <-edgesC:
			edges.Reset(r.netEdgesInterval)
			if !r.ceiling().NetEdges {
				continue
			}
			e, err := r.netEdges()
			if err != nil {
				r.log.WarnContext(ctx, "read network edges", "err", err)
				continue
			}
			if e == nil {
				continue // not supported on this platform
			}
			msg = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_NetEdges{NetEdges: e}}
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

// applyCeiling takes the ceiling the hub set for this device: unless the
// agent runs with --local-ceiling, it checks it, saves it and makes it the
// hub's part of the effective ceiling. It reports whether the effective
// ceiling changed, and then wakes sendLoop to report it.
func (r *runner) applyCeiling(ctx context.Context, cfg *agentv1.CeilingConfig) bool {
	if r.ceilings.locked {
		r.log.InfoContext(ctx, "capability ceiling from the hub ignored: the agent runs with --local-ceiling")
		return false
	}
	c, err := checkHubCeiling(ceilingOf(cfg.GetCeiling()))
	if err != nil {
		r.log.WarnContext(ctx, "capability ceiling from the hub refused", "err", err)
		return false
	}
	before := r.ceiling()
	if !r.ceilings.setHub(c) {
		return false
	}
	if err := writeCeilingFile(r.cfg.DataDir, c); err != nil {
		// Not fatal: the ceiling in memory applies, and the hub sends it
		// again on the next connect.
		r.log.WarnContext(ctx, "save the capability ceiling", "err", err)
	}
	after := r.ceiling()
	if after.equal(before) {
		return false
	}
	r.log.InfoContext(ctx, "capability ceiling changed by the hub", "exec", len(after.Exec), "restart", len(after.Restart),
		"probe", after.Probe, "logs", len(after.Logs), "shell", after.Shell, "scan", len(after.Scan),
		"net_edges", after.NetEdges, "docker", after.Docker, "docker_read", after.DockerRead)
	select {
	case r.ceilingChanged <- struct{}{}:
	default:
	}
	return true
}
