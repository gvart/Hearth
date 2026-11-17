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
}

// NewHandler serves EnrollService to anyone (the token is the credential) and
// AgentService only to clients with a valid, unrevoked certificate from the CA.
func NewHandler(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(agentv1connect.NewEnrollServiceHandler(NewEnroller(cfg.Store, cfg.CA, cfg.Policy, cfg.Log)))
	reg := cfg.Registry
	if reg == nil {
		reg = NewRegistry(RegistryConfig{Store: cfg.Store, Log: cfg.Log})
	}
	path, h := agentv1connect.NewAgentServiceHandler(NewAgentStream(cfg.Log, cfg.HeartbeatInterval, reg))
	mux.Handle(path, requireClientCert(cfg.Store.Certs(), cfg.Log, h))
	return mux
}

// TLSConfig is the hub's listener config. Client certificates are optional at
// the TLS layer (enrollment has none yet) but, when given, must chain to the CA;
// AgentService then insists on one.
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
