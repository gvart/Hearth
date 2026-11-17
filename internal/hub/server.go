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

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
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
	stream := NewAgentStream(cfg.Log, cfg.HeartbeatInterval, reg)
	stream.leadership = lead
	path, h := agentv1connect.NewAgentServiceHandler(stream)
	mux.Handle(path, requireClientCert(cfg.Store.Certs(), cfg.Log, EndOnStop(cfg.Stopping, h)))
	return mux
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancelCause(r.Context())
		defer cancel(nil)
		stop := context.AfterFunc(stopping, func() {
			cancel(errStopping)
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
// into the request context. The store is consulted on every request so
// revocations by another process (the CLI) take effect immediately.
func requireClientCert(certs certChecker, log *slog.Logger, next http.Handler) http.Handler {
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
		switch err := certs.Check(ctx, serial, deviceID); {
		case errors.Is(err, store.ErrCertRevoked):
			deny("certificate revoked", "device_id", deviceID, "serial", serial)
			return
		case errors.Is(err, store.ErrNotFound):
			deny("certificate unknown", "device_id", deviceID, "serial", serial)
			return
		case err != nil:
			log.ErrorContext(ctx, "check client certificate", "device_id", deviceID, "err", err)
			_ = errWriter.Write(w, r, connect.NewError(connect.CodeUnavailable, errors.New("cannot check certificate")))
			return
		}
		next.ServeHTTP(w, r.WithContext(withDeviceID(ctx, deviceID)))
	})
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
