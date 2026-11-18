// SPDX-License-Identifier: AGPL-3.0-only

// Package mcpserver is the hub's Model Context Protocol server: the tools an
// AI assistant such as Claude Code uses to see and operate the homelab. It
// serves streamable HTTP behind bearer tokens (store.MCPTokens); `hearth mcp`
// bridges stdio clients to it.
//
// Every tool call goes through policy as the actor mcp/<token name>, with
// the token's scope as the highest class it may request (policy.WithScope),
// and lands in the audit log. Only the hub uses this package.
package mcpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// Path is where the hub serves MCP.
const Path = "/mcp"

// TokenPrefix starts every MCP token, so one is easy to recognise (and to
// scan for in leaked logs).
const TokenPrefix = "hearth_mcp_" //nolint:gosec // a prefix, not a credential

// Devices lists the hub's devices: store.Devices.
type Devices interface {
	List(ctx context.Context) ([]store.Device, error)
}

// Tokens checks bearer tokens: store.MCPTokens.
type Tokens interface {
	Check(ctx context.Context, secret string) (store.MCPToken, error)
}

// Agents runs requests on devices through their agents: *hub.Agents.
type Agents interface {
	Check(ctx context.Context, device string, req *agentv1.ExecRequest) error
	Exec(ctx context.Context, device string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error)
}

// Kube reads and acts on adopted Kubernetes clusters: *kubernetes.Manager.
type Kube interface {
	Clusters() []kubernetes.ClusterInfo
	Snapshot(ctx context.Context, id string) (kubernetes.Snapshot, error)
	Logs(ctx context.Context, actorKind, actorID, id, namespace, pod, container string, tail int) (string, error)
	Act(ctx context.Context, actorKind, actorID, id string, req kubernetes.ActionRequest) (kubernetes.ActionResult, error)
}

// Config holds the server's dependencies.
type Config struct {
	Devices Devices
	// Live overlays what the hub knows of a device beyond the store, such
	// as Registry.Live; nil means the store's view.
	Live   func(store.Device) store.Device
	Tokens Tokens
	Policy *policy.Engine
	Agents Agents
	// Kube is nil when Kubernetes clusters are not served.
	Kube Kube
	// Metrics is nil when no Prometheus is configured.
	Metrics automation.Metrics
	// AutomationsDir is where apply_automation writes automation files.
	AutomationsDir string
	Version        string
	Log            *slog.Logger
}

// Handler serves MCP over streamable HTTP (see protocol.go). Each request
// must carry a valid MCP token as a bearer token, and is answered with the
// tools the token's scope allows. Every request authenticates on its own,
// so a revoked token stops at once, and there are no sessions to keep.
func Handler(cfg Config) http.Handler {
	if cfg.Live == nil {
		cfg.Live = func(d store.Device) store.Device { return d }
	}
	return requireToken(cfg.Tokens, cfg.Log, &endpoint{cfg: cfg})
}

type tokenKey struct{}

// requireToken admits only requests with a valid, unrevoked MCP token as
// their bearer token, and puts the token into the request context.
func requireToken(tokens Tokens, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deny := func(reason string) {
			log.WarnContext(r.Context(), "mcp request rejected: "+reason, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="hearth"`)
			http.Error(w, reason, http.StatusUnauthorized)
		}
		scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || secret == "" {
			deny("bearer token required")
			return
		}
		tok, err := tokens.Check(r.Context(), strings.TrimSpace(secret))
		switch {
		case errors.Is(err, store.ErrNotFound):
			deny("unknown token")
			return
		case errors.Is(err, store.ErrTokenRevoked):
			deny("token revoked")
			return
		case err != nil:
			log.ErrorContext(r.Context(), "check mcp token", "err", err)
			http.Error(w, "cannot check token", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenKey{}, tok)))
	})
}

// session is one request's view of the server: the token it came with.
type session struct {
	cfg Config
	tok store.MCPToken
}

// offered returns the tools this session's token may use.
func (s *session) offered() []tool {
	var out []tool
	for _, t := range s.tools() {
		if policy.Within(t.class, policy.Class(s.tok.Scope)) {
			out = append(out, t)
		}
	}
	return out
}

// do runs fn through policy as this session's token, capped by its scope.
// A held request waits for its approval.
func (s *session) do(ctx context.Context, req policy.Request, fn func(context.Context) error) error {
	req.ActorKind, req.ActorID = policy.ActorMCP, s.tok.Name
	return s.cfg.Policy.Do(s.scoped(ctx), req, fn)
}

// scoped returns ctx capped by the token's scope, for calls that go
// through policy on their own (the Kubernetes manager's).
func (s *session) scoped(ctx context.Context) context.Context {
	return policy.WithScope(ctx, policy.Class(s.tok.Scope))
}
