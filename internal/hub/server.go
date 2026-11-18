// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/pki"
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
	// Prometheus reads device chart series from an existing Prometheus
	// server. Nil means none is configured: charts report not_configured.
	Prometheus *prometheus.Reader
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
	stream.certs, stream.authority = cfg.Store.Certs(), authority
	path, h := agentv1connect.NewAgentServiceHandler(stream)
	mux.Handle(path, requireClientCert(cfg.Store.Certs(), cfg.Log, authority,
		EndOnStop(cfg.Stopping, reg.endOnStepDown(h))))
	return mux
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
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		NextProtos:   []string{"h2", "http/1.1"},
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
func requireClientCert(certs certChecker, log *slog.Logger, authority func() error, next http.Handler) http.Handler {
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
		next.ServeHTTP(w, r.WithContext(context.WithValue(withDeviceID(ctx, deviceID), serialKey{}, serial)))
	})
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
