// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/mcpserver"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// webAdminRoutes registers what the CLI does on a hub host and the web UI
// does behind the admin session: revoking a device, MCP tokens and changing
// the admin password. The sensitive ones need the password again (see
// recentAuth).
func (a *api) webAdminRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/devices/{id}/revoke", a.auth(a.revokeDevice))
	mux.Handle("GET /api/v1/mcp/tokens", a.auth(a.listMCPTokens))
	mux.Handle("POST /api/v1/mcp/tokens", a.auth(a.createMCPToken))
	mux.Handle("DELETE /api/v1/mcp/tokens/{name}", a.auth(a.revokeMCPToken))
	mux.Handle("PUT /api/v1/admin/password", a.auth(a.changePassword))
}

// decodeJSON reads a small JSON body into v, or answers the request and
// returns false. An empty body leaves v as it is.
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, v any, usage string) bool {
	if r.ContentLength == 0 && r.Header.Get("Content-Type") == "" {
		return true
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be "+usage)
		return false
	}
	return true
}

// RevokedJSON answers a device revocation.
type RevokedJSON struct {
	Revoked int `json:"revoked"`
}

// revokeDevice revokes every certificate of a device, as `hearth device
// revoke` does: dangerous, and only with the password entered again. A
// connected agent is cut off at its next heartbeat.
func (a *api) revokeDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var n int
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DeviceRevoke, Target: id,
		Precheck: a.recentAuth(r),
	}, func(ctx context.Context) error {
		var err error
		n, err = a.store.Certs().RevokeDevice(ctx, id, a.now())
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "the device has no certificates")
		return
	}
	if err != nil {
		a.writeActionError(w, r, "revoke the device", err)
		return
	}
	a.log.InfoContext(r.Context(), "device revoked from the web UI", "device", id, "certificates", n)
	writeJSON(w, http.StatusOK, RevokedJSON{Revoked: n})
}

// mcpTokenName is what an MCP token's name looks like, as `hearth mcp token
// create` checks it: it names the actor in the audit log.
var mcpTokenName = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`) })

// MCPTokenJSON is an MCP token in the list. Its secret is never served
// again: only its hash is stored.
type MCPTokenJSON struct {
	Name      string     `json:"name"`
	Scope     string     `json:"scope"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func (a *api) listMCPTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := a.store.MCPTokens().List(r.Context())
	if errors.Is(err, store.ErrSchemaTooOld) {
		writeError(w, http.StatusConflict, "schema_too_old", "the hub cluster's database predates MCP tokens: upgrade every hub of the cluster first")
		return
	}
	if err != nil {
		a.writeActionError(w, r, "list MCP tokens", err)
		return
	}
	out := make([]MCPTokenJSON, 0, len(toks))
	for _, t := range toks {
		item := MCPTokenJSON{Name: t.Name, Scope: t.Scope, CreatedAt: t.CreatedAt.UTC()}
		if !t.RevokedAt.IsZero() {
			at := t.RevokedAt.UTC()
			item.RevokedAt = &at
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, struct {
		Tokens []MCPTokenJSON `json:"tokens"`
	}{Tokens: out})
}

// CreatedMCPTokenJSON answers the creation of an MCP token. Secret is shown
// this once and never logged.
type CreatedMCPTokenJSON struct {
	Name   string `json:"name"`
	Scope  string `json:"scope"`
	Secret string `json:"secret"`
	// Path is the hub's MCP endpoint, for the client's configuration.
	Path string `json:"path"`
}

// createMCPToken creates an MCP token, as `hearth mcp token create` does:
// dangerous, since a token may carry the dangerous scope, and only with the
// password entered again.
func (a *api) createMCPToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
	}
	if !decodeJSON(w, r, maxTokenBody, &body, `{"name": "...", "scope": "read|safe|dangerous"}`) {
		return
	}
	if !mcpTokenName().MatchString(body.Name) {
		writeError(w, http.StatusBadRequest, "bad_name",
			"the name must be 1 to 64 lowercase letters, digits, ., - or _, starting with a letter or digit")
		return
	}
	if body.Scope == "" {
		body.Scope = string(policy.Safe)
	}
	switch policy.Class(body.Scope) {
	case policy.Read, policy.Safe, policy.Dangerous:
	default:
		writeError(w, http.StatusBadRequest, "bad_scope", "the scope must be read, safe or dangerous")
		return
	}
	secret := mcpserver.TokenPrefix + strings.ToLower(rand.Text())
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.MCPTokenCreate, Target: body.Name,
		Detail: map[string]any{"scope": body.Scope}, Precheck: a.recentAuth(r),
	}, func(ctx context.Context) error {
		return a.store.MCPTokens().Create(ctx, body.Name, secret, body.Scope, a.now())
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, CreatedMCPTokenJSON{Name: body.Name, Scope: body.Scope, Secret: secret, Path: mcpserver.Path})
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old", "the hub cluster's database predates MCP tokens: upgrade every hub of the cluster first")
	case store.IsDomainError(err):
		writeError(w, http.StatusConflict, "name_taken", "the name is taken: names are never reused, even revoked ones")
	default:
		a.writeActionError(w, r, "create the MCP token", err)
	}
}

// revokeMCPToken revokes an MCP token, as `hearth mcp token revoke` does: the
// hub refuses it from its next request.
func (a *api) revokeMCPToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx, reach := store.WithReach(r.Context())
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.MCPTokenRevoke, Target: name,
		Precheck: a.recentAuth(r),
	}, func(ctx context.Context) error { return a.store.MCPTokens().Revoke(ctx, name, a.now()) })
	switch {
	case err == nil:
		writeReach(w, *reach)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no MCP token of this name is in use")
	default:
		a.writeActionError(w, r, "revoke the MCP token", err)
	}
}

// changePassword sets a new admin password for a signed-in admin who gives
// the current one, checked as login checks it and under login's rate limit.
// It follows the modes (admin.set_password by web), and ends every session.
// Resetting a lost password stays `hearth admin set-password` on the hub host.
func (a *api) changePassword(w http.ResponseWriter, r *http.Request) {
	ctx, reach := store.WithReach(r.Context())
	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decodeJSON(w, r, maxLoginBody, &body, `{"current_password": "...", "new_password": "..."}`) {
		return
	}
	if len(body.New) < MinPasswordLen {
		writeError(w, http.StatusBadRequest, "bad_password", "the new password needs at least 8 characters")
		return
	}
	wrong := false
	if body.Current != "" {
		if ok, wait := a.logins.allow(remoteHost(r)); !ok {
			writeRetry(w, http.StatusTooManyRequests, wait, "rate_limited", "too many password attempts; try again later")
			return
		}
		defer func() {
			if !wrong {
				a.logins.refund(remoteHost(r))
			}
		}()
	}
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.AdminSetPassword, Target: adminUser,
	}, func(ctx context.Context) error {
		if body.Current == "" {
			return errNoPassword
		}
		err := a.checkAdminPassword(ctx, body.Current)
		wrong = errors.Is(err, errWrongPassword)
		if err != nil {
			return err
		}
		var hash string
		var herr error
		// Hashing costs as much as a verification: one at a time.
		if err := a.verify.do(ctx, a.verifyWait, func() { hash, herr = hashPassword(body.New, a.argon) }); err != nil {
			return err
		}
		if herr != nil {
			return herr
		}
		if err := a.store.Admin().SetPasswordHash(ctx, hash); err != nil {
			return err
		}
		a.reauths.forgetAll()
		return nil
	})
	switch {
	case err == nil:
		a.log.InfoContext(ctx, "admin password changed from the web UI: every session ended", "remote", remoteHost(r))
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // clears the cookie; see login
			Name: sessionCookieName(r), Value: "", Path: "/", MaxAge: -1,
			Secure: r.TLS != nil, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		writeReach(w, *reach)
	case errors.Is(err, errWrongPassword), errors.Is(err, errNoPassword):
		a.log.WarnContext(ctx, "password change refused: wrong or missing current password", "remote", remoteHost(r))
		writeError(w, http.StatusForbidden, "reauth_failed", "the current password was missing or wrong")
	case errors.Is(err, errVerifyBusy):
		writeRetry(w, http.StatusServiceUnavailable, a.verifyWait, "busy", "the hub is busy checking other passwords; try again shortly")
	default:
		a.writeActionError(w, r, "change the password", err)
	}
}
