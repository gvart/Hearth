// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/integrations/proxmox"
	"github.com/gvart/hearth/internal/metrics"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// Config holds the hub server's dependencies.
type Config struct {
	Store             *store.Store
	CA                *pki.CA
	Policy            *policy.Engine
	Log               *slog.Logger
	HeartbeatInterval time.Duration
	// Registry tracks device presence and publishes events. Share one between
	// NewHandler and NewHTTPHandler and Run it. If nil, NewHandler creates one
	// that records facts and heartbeats but never sweeps devices offline.
	Registry *Registry
	// AgentHosts are the names in the hub's TLS certificate and AgentPort the
	// port agents connect to. The web API builds join commands from them.
	AgentHosts []string
	AgentPort  string
	// HTTPPort is the plain-HTTP listener's port, which serves install.sh.
	// Install commands made over HTTPS point there. Default DefaultHTTPPort.
	HTTPPort string
	// Version is the hub's own version. When it is a release tag (vX.Y.Z or
	// vX.Y.Z-rc.N), install commands pin the agent to it with --version.
	Version string
	// Stopping is cancelled when the hub begins shutting down. Agent streams
	// then end at once, so a graceful shutdown need not wait them out. If nil,
	// they end only when the agent hangs up or the server closes.
	Stopping context.Context
	// Leadership says whether this hub is the cluster leader. Followers refuse
	// agent streams and enrollment and name the leader. If nil, the hub is a
	// single node: always the leader, and Welcome lists no hubs, so agents
	// keep only the URL they joined with.
	Leadership Leadership
	// Ready is closed once a clustered hub has caught up with the cluster
	// after it started. Until then the JSON API waits briefly and answers 503
	// catching_up rather than serve state older than what the hub already
	// acknowledged. Nil, as on a standalone hub, means always ready.
	Ready <-chan struct{}
	// VerifyPassword checks login passwords, one at a time. If nil, they are
	// checked in this process; the hub binary passes ChildVerifier.
	VerifyPassword PasswordVerifier
	// Prometheus reads device chart series from an existing Prometheus
	// server. Nil means none is configured: charts report not_configured.
	Prometheus *prometheus.Reader
	// Beszel holds what the hub last read from a Beszel hub. Nil means none
	// is configured: GET /api/v1/beszel/systems reports not_configured.
	Beszel BeszelSnapshotter
	// Talos holds what the hub last read from the Talos API. Nil means no
	// talosconfig is configured: GET /api/v1/talos/nodes reports
	// not_configured.
	Talos TalosSnapshotter
	// NetEdges keeps the network edges agents report and serves them under
	// /api/v1/devices/{id}/net-edges. Nil drops them.
	NetEdges *NetEdges
	// Metrics stores the host metrics agents send and serves device charts
	// when no Prometheus is configured. Nil drops the metrics.
	Metrics *metrics.Store
	// Agents runs exec requests over the open agent streams. Share one with
	// whatever sends them (the automations). If nil, NewHandler creates one.
	Agents *Agents
	// DashboardAudit spaces out the audit rows of dashboard reads; run it
	// (DashboardAudit.Run) so that its counts are flushed. If nil, the API
	// makes one that only writes a key's counts with its next row.
	DashboardAudit *DashboardAudit
	// Kube serves adopted Kubernetes clusters under /api/v1/kube and streams
	// their changes on /api/v1/events. Nil disables both.
	Kube *kubernetes.Manager
	// Proxmox serves adopted Proxmox VE servers under /api/v1/proxmox. Nil
	// disables it.
	Proxmox *proxmox.Manager
	// Plugins serves the hub's exec plugins under /api/v1/plugins. Nil
	// disables it.
	Plugins *plugins.Manager
	// Notify serves the notification channels under /api/v1/notify. Nil
	// disables it.
	Notify *notify.Notifier
	// ConfigDrift compares the configuration of a cluster's hubs for
	// GET /api/v1/cluster/config-drift; nil on a standalone hub. Its result is
	// served as is, so it must hold no digests or file contents.
	ConfigDrift func(context.Context) (any, error)
	// Runbooks serves the runbooks under /api/v1/runbooks and
	// /api/v1/runbook-runs. Nil disables them.
	Runbooks *automation.Runbooks
	// AutomationsDir is the directory of automation files the web UI's editor
	// reads and writes under /api/v1/automations, when AutomationDocs is
	// nil. Empty, with no AutomationDocs, disables it.
	AutomationsDir string
	// AutomationDocs are the automation documents of the store, which the
	// editor reads and writes instead of AutomationsDir.
	AutomationDocs automation.DocStore
	// AutomationKinds are the step types the hub runs: the editor validates
	// files with them, as the hub will when it loads them.
	AutomationKinds automation.Kinds
	// AutomationsLock makes each save of an automation file one step: share
	// it with every other writer of the directory, such as the MCP server.
	// Nil means the editor's own.
	AutomationsLock sync.Locker
	// TelemetryOff is HEARTH_TELEMETRY=off: the web UI does not ask about
	// telemetry, and the answer cannot be changed.
	TelemetryOff bool
	// ShellIdleTimeout ends a web terminal session without input for this
	// long; ShellMaxDuration ends any this long after it opened. Zero means
	// DefaultShellIdleTimeout and DefaultShellMaxDuration. Terminals are
	// served only with Agents set.
	ShellIdleTimeout time.Duration
	ShellMaxDuration time.Duration
}

// NewHandler serves EnrollService to anyone (the token is the credential) and
// AgentService only to clients with a valid, unrevoked certificate from the CA.
func NewHandler(cfg Config) http.Handler {
	lead := leadershipOf(cfg)
	mux := http.NewServeMux()
	enroller := NewEnroller(cfg.Store, cfg.CA, cfg.Policy, cfg.Log)
	enroller.leadership = lead
	mux.Handle(agentv1connect.NewEnrollServiceHandler(enroller))
	reg := cfg.Registry
	if reg == nil {
		reg = NewRegistry(RegistryConfig{Store: cfg.Store, Log: cfg.Log})
	}
	authority := reg.certAuthority(lead)
	stream := NewAgentStream(cfg.Log, cfg.HeartbeatInterval, reg)
	stream.leadership = lead
	stream.certs, stream.authority, stream.pins, stream.audit = cfg.Store.Certs(), authority, cfg.Store.Certs(), cfg.Store.Audit()
	stream.ca, stream.rotations, stream.renew = cfg.CA, cfg.Store.CARotations(), cfg.Store.Certs()
	stream.metrics = cfg.Metrics
	stream.netEdges = cfg.NetEdges
	if cfg.Agents != nil {
		stream.agents = cfg.Agents
	}
	path, h := agentServiceHandler(stream)
	mux.Handle(path, requireClientCert(cfg.Store.Certs(), cfg.CA, cfg.Log, authority,
		EndOnStop(cfg.Stopping, reg.endOnStepDown(abortableStream(h)))))
	return mux
}

// maxAgentMessage caps one message an agent sends. The largest an agent
// sends legitimately are well below it: a batch of 64 log lines of at most
// 4 kB each, a shell output chunk of 32 kB, a scan of at most 1024 hosts,
// network edges of at most 1024 entries, and its facts.
const maxAgentMessage = 4 << 20

// agentServiceHandler serves stream, refusing any message larger than
// maxAgentMessage: the stream ends with ResourceExhausted.
func agentServiceHandler(stream *AgentStream) (string, http.Handler) {
	return agentv1connect.NewAgentServiceHandler(stream, connect.WithReadMaxBytes(maxAgentMessage))
}

// certAuthority returns what a hub that cannot vouch for its own store
// answers instead of rejecting a client certificate, or nil when it can. A
// standalone hub always can. A clustered hub can only within a leadership
// term, which starts after the barrier, so its store holds every committed
// certificate and revocation. A follower, a hub catching up after a start or a
// leader taking over may lag the cluster: a certificate it does not know yet,
// or a revocation it has not seen undone, says nothing about the device. It
// answers NotLeader (naming the leader) or Unavailable, never Unauthenticated.
func (r *Registry) certAuthority(lead Leadership) func() error {
	if !r.replicated {
		return func() error { return nil }
	}
	return func() error {
		if !lead.IsLeader() {
			return notLeaderError(lead)
		}
		if term := r.currentTerm(); term == nil || term.Err() != nil {
			return connect.NewError(connect.CodeUnavailable, errors.New("this hub is taking over as the cluster leader; retry shortly"))
		}
		return nil
	}
}

// errSteppedDown is the cause of an agent stream ended because this hub
// stopped leading the cluster.
var errSteppedDown = errors.New("no longer the cluster leader")

type termKey struct{}

// endOnStepDown ties each agent stream on a clustered hub to the leadership
// term it started in: the stream ends, with cause errSteppedDown, when the
// term ends. A request outside any term carries none and is refused by
// AgentStream.Connect. On a standalone hub it returns next unchanged.
func (r *Registry) endOnStepDown(next http.Handler) http.Handler {
	if !r.replicated {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		term := r.currentTerm()
		if term == nil {
			next.ServeHTTP(w, req)
			return
		}
		endOn(term, errSteppedDown, next).ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), termKey{}, term)))
	})
}

// NewTLSHandler serves the agent services exactly as NewHandler does and every
// other path from web, the UI and JSON API, so browsers can use the hub over
// HTTPS on the agent port. web authenticates by session cookie only: a client
// certificate grants nothing outside AgentService.
func NewTLSHandler(cfg Config, web http.Handler) http.Handler {
	agents := NewHandler(cfg)
	mux := http.NewServeMux()
	mux.Handle("/"+agentv1connect.EnrollServiceName+"/", agents)
	mux.Handle("/"+agentv1connect.AgentServiceName+"/", agents)
	mux.Handle("/", web)
	return mux
}

// errStreamStalled is the cause of an agent stream the hub tore down because
// the agent stopped taking what the hub sends.
var errStreamStalled = errors.New("the agent stopped reading its stream")

type abortKey struct{}

// abortableStream lets the handler of an agent stream tear it down without
// the agent's help: a send blocked on a peer that stopped reading ends only
// with a write deadline, and the stream's Receive only with its body closed.
// The agent sees the stream reset, which ends its shells.
func abortableStream(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancelCause(r.Context())
		defer cancel(nil)
		rc := http.NewResponseController(w)
		abort := sync.OnceFunc(func() {
			cancel(errStreamStalled)
			_ = rc.SetWriteDeadline(time.Now())
			_ = r.Body.Close()
		})
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, abortKey{}, abort)))
	})
}

// streamAbort is the function that tears down the agent stream of ctx.
func streamAbort(ctx context.Context) func() {
	if abort, ok := ctx.Value(abortKey{}).(func()); ok {
		return abort
	}
	return func() {}
}

// errStopping is the cause of a request context cancelled by EndOnStop.
var errStopping = errors.New("hub shutting down")

// EndOnStop wraps a handler of long-lived streams so that each request ends
// once stopping is cancelled: its context is cancelled with cause errStopping
// and its body closed, which unblocks a handler waiting on either. The handler
// then finishes its response normally. A nil stopping returns next unchanged.
func EndOnStop(stopping context.Context, next http.Handler) http.Handler {
	if stopping == nil {
		return next
	}
	return endOn(stopping, errStopping, next)
}

// endOn ends each request when done is cancelled: its context is cancelled
// with cause and its body closed.
func endOn(done context.Context, cause error, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancelCause(r.Context())
		defer cancel(nil)
		stop := context.AfterFunc(done, func() {
			cancel(cause)
			_ = r.Body.Close()
		})
		defer stop()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TLSConfig is the hub's listener config. Client certificates are optional at
// the TLS layer (enrollment and browsers have none) but, when given, must chain
// to the CA; AgentService then insists on one.
func TLSConfig(ca *pki.CA, serverCert tls.Certificate) *tls.Config {
	return TLSConfigFunc(ca, func() *tls.Certificate { return &serverCert })
}

// TLSConfigFunc is TLSConfig serving the certificate serverCert returns at
// each handshake. The CAs client certificates must chain to are ca's at each
// handshake, so a hub CA rotation reaches new connections without a restart.
func TLSConfigFunc(ca *pki.CA, serverCert func() *tls.Certificate) *tls.Config {
	protos := []string{"h2", "http/1.1"}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: protos,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{*serverCert()},
				ClientAuth:   tls.VerifyClientCertIfGiven,
				ClientCAs:    ca.Pool(),
				NextProtos:   protos,
				// A resumed session skips chain verification: one from
				// before a hub CA rotation finished must not outlive it.
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) > 0 && ca.IssuerOf(cs.PeerCertificates[0]) == nil {
						return errors.New("client certificate is not from a trusted hub CA")
					}
					return nil
				},
			}, nil
		},
	}
}

// certChecker is the part of store.Certs the auth middleware needs.
type certChecker interface {
	Check(ctx context.Context, serial, deviceID string) error
}

// requireClientCert admits only requests with a verified client certificate
// that the hub issued and has not revoked, and puts the device ID it carries
// and the certificate serial into the request context. The store is consulted
// on every request so revocations by another process (the CLI) refuse the
// next connect; AgentStream re-checks open streams on every heartbeat. A
// certificate the store does not know or has revoked is rejected only when
// authority returns nil; otherwise its error is the answer (see
// Registry.certAuthority).
func requireClientCert(certs certChecker, ca *pki.CA, log *slog.Logger, authority func() error, next http.Handler) http.Handler {
	errWriter := connect.NewErrorWriter()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		deny := func(reason string, args ...any) {
			log.WarnContext(ctx, "agent rejected: "+reason, args...)
			_ = errWriter.Write(w, r, connect.NewError(connect.CodeUnauthenticated, errors.New(reason)))
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			deny("client certificate required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		// The connection may predate the end of a hub CA rotation.
		if ca != nil && ca.IssuerOf(leaf) == nil {
			deny("client certificate of a hub CA no longer trusted")
			return
		}
		deviceID, err := pki.DeviceID(leaf)
		if err != nil {
			deny("client certificate has no device identity")
			return
		}
		serial := pki.SerialString(leaf)
		err = certs.Check(ctx, serial, deviceID)
		if errors.Is(err, store.ErrCertRevoked) || errors.Is(err, store.ErrNotFound) {
			if aerr := authority(); aerr != nil {
				log.DebugContext(ctx, "agent certificate not judged: this hub's store may lag the cluster",
					"device_id", deviceID, "err", aerr)
				_ = errWriter.Write(w, r, aerr)
				return
			}
		}
		switch {
		case errors.Is(err, store.ErrCertRevoked):
			log.WarnContext(ctx, "agent rejected: certificate revoked", "device_id", deviceID, "serial", serial)
			_ = errWriter.Write(w, r, certRejection(true))
			return
		case errors.Is(err, store.ErrNotFound):
			deny("certificate unknown", "device_id", deviceID, "serial", serial)
			return
		case err != nil:
			log.ErrorContext(ctx, "check client certificate", "device_id", deviceID, "err", err)
			_ = errWriter.Write(w, r, connect.NewError(connect.CodeUnavailable, errors.New("cannot check certificate")))
			return
		}
		ctx = context.WithValue(withDeviceID(ctx, deviceID), serialKey{}, serial)
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, chainKey{}, r.TLS.VerifiedChains[0])))
	})
}

type chainKey struct{}

// chainFrom returns the verified chain of the client certificate set by
// requireClientCert: the certificate first, the CA that issued it last.
func chainFrom(ctx context.Context) ([]*x509.Certificate, bool) {
	c, ok := ctx.Value(chainKey{}).([]*x509.Certificate)
	return c, ok && len(c) > 0
}

// certRejection is the error for a client certificate this hub has judged
// revoked (revoked true) or does not know. Both are Unauthenticated; a
// revocation also carries the CertificateRevoked detail, on which the agent
// stops instead of retrying.
func certRejection(revoked bool) error {
	if !revoked {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("certificate unknown"))
	}
	err := connect.NewError(connect.CodeUnauthenticated, errors.New("certificate revoked"))
	if d, derr := connect.NewErrorDetail(&agentv1.CertificateRevoked{}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

type serialKey struct{}

// serialFrom returns the client certificate serial set by requireClientCert.
func serialFrom(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(serialKey{}).(string)
	return s, ok && s != ""
}

type deviceIDKey struct{}

func withDeviceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, deviceIDKey{}, id)
}

// deviceIDFrom returns the authenticated device ID set by requireClientCert.
func deviceIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(deviceIDKey{}).(string)
	return id, ok && id != ""
}
