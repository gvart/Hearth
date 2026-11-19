// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// Dashboard tokens (docs/homepage.md).
//
// A dashboard such as Homepage reads Hearth with a read-only token that a
// signed-in admin creates and revokes. The token is a bearer token for one
// endpoint, GET /api/v1/dashboard/summary: device counts and per-device
// states, no addresses, facts or labels. It is never a session, an MCP token
// or a panel link, and those are never one. Every read is decided by policy
// as ActorDashboard, token/<token id>, action dashboard.read (class read).
//
// Dashboards poll every few seconds, so the audit log gets the first
// allowed read of each token per hour, not every read, and the first denied
// read per source address and actor per hour. Each row counts the reads (or
// denials) since the previous one that got none.

const (
	// dashboardReadBurst and dashboardReadEvery set the per-token rate of
	// reads: Homepage polls each widget every 10 s by default.
	dashboardReadBurst = 20
	dashboardReadEvery = time.Second
	// dashboardAuditEvery is how often a token's reads, or a source's
	// denied reads, get an audit row.
	dashboardAuditEvery = time.Hour
	// maxDashboardDevices caps the devices listed in a summary; the counts
	// cover all of them.
	maxDashboardDevices = 200
	// maxDashboardTokenName bounds a token's name, in runes.
	maxDashboardTokenName = 100
	// maxDashboardTokenTTL bounds a token's expiry; none means never.
	maxDashboardTokenTTL = 10 * 365 * 24 * time.Hour
	// dashboardSummaryVersion is the version of the summary's JSON shape.
	dashboardSummaryVersion = 1
)

// DashboardCountsJSON counts devices by status. Offline is every device not
// online, those never heard from included.
type DashboardCountsJSON struct {
	Total   int `json:"total"`
	Online  int `json:"online"`
	Offline int `json:"offline"`
}

// DashboardDeviceJSON is what a dashboard sees of a device.
type DashboardDeviceJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Status is online, offline or unknown.
	Status   string     `json:"status"`
	LastSeen *time.Time `json:"last_seen"`
}

// DashboardSummaryJSON is the body of GET /api/v1/dashboard/summary. Its
// shape is stable within a version.
type DashboardSummaryJSON struct {
	Version int                 `json:"version"`
	Counts  DashboardCountsJSON `json:"counts"`
	// Devices are the first maxDashboardDevices devices.
	Devices []DashboardDeviceJSON `json:"devices"`
	// Truncated is true when Devices leaves some out.
	Truncated bool `json:"truncated"`
}

// DashboardTokenJSON is a dashboard token, without its secret.
type DashboardTokenJSON struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	// Status is active, expired or revoked.
	Status string `json:"status"`
}

// CreatedDashboardTokenJSON is the answer to a token's creation: the only
// time its secret is shown.
type CreatedDashboardTokenJSON struct {
	Token  DashboardTokenJSON `json:"token"`
	Secret string             `json:"secret"`
}

func (a *api) dashboardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/dashboard/summary", a.dashboardSummary)
	mux.Handle("GET /api/v1/dashboard/tokens", a.auth(a.listDashboardTokens))
	mux.Handle("POST /api/v1/dashboard/tokens", a.auth(a.createDashboardToken))
	mux.Handle("DELETE /api/v1/dashboard/tokens/{id}", a.auth(a.revokeDashboardToken))
}

func dashboardTokenJSON(t store.DashboardToken, now time.Time) DashboardTokenJSON {
	out := DashboardTokenJSON{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt, Status: "active"}
	if !t.ExpiresAt.IsZero() {
		exp := t.ExpiresAt
		out.ExpiresAt = &exp
		if !now.Before(exp) {
			out.Status = "expired"
		}
	}
	if !t.RevokedAt.IsZero() {
		rev := t.RevokedAt
		out.RevokedAt, out.Status = &rev, "revoked"
	}
	return out
}

func (a *api) listDashboardTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := a.store.DashboardTokens().List(r.Context())
	if err != nil {
		a.writeDashboardTokenError(w, r, "list dashboard tokens", err)
		return
	}
	now := a.now()
	out := struct {
		Tokens []DashboardTokenJSON `json:"tokens"`
	}{Tokens: make([]DashboardTokenJSON, 0, len(toks))}
	for _, t := range toks {
		out.Tokens = append(out.Tokens, dashboardTokenJSON(t, now))
	}
	writeJSON(w, http.StatusOK, out)
}

// createDashboardToken makes a token. Its secret is in the answer and
// nowhere else: the store keeps its hash, the audit log its ID.
func (a *api) createDashboardToken(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var body struct {
		Name string `json:"name"`
		// ExpiresIn is a Go duration, as "720h"; empty for a token that
		// never expires.
		ExpiresIn string `json:"expires_in"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"name": "...", "expires_in": "720h"}`)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || utf8.RuneCountInString(name) > maxDashboardTokenName || !utf8.ValidString(name) {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("name must be 1 to %d characters", maxDashboardTokenName))
		return
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	tok := store.DashboardToken{ID: strings.ToLower(rand.Text()), Name: name, CreatedAt: now}
	if body.ExpiresIn != "" {
		ttl, err := time.ParseDuration(body.ExpiresIn)
		if err != nil || ttl <= 0 || ttl > maxDashboardTokenTTL {
			writeError(w, http.StatusBadRequest, "bad_request", "expires_in must be a positive duration, as 720h")
			return
		}
		tok.ExpiresAt = now.Add(ttl)
	}
	detail := map[string]any{"name": name}
	if !tok.ExpiresAt.IsZero() {
		detail["expires_at"] = tok.ExpiresAt
	}
	secret := rand.Text()
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DashboardTokenCreate,
		Target: "token/" + tok.ID, Detail: detail,
	}, func(ctx context.Context) error { return a.store.DashboardTokens().Create(ctx, tok, secret) })
	if err != nil {
		a.writeDashboardTokenError(w, r, "create dashboard token", err)
		return
	}
	writeJSON(w, http.StatusCreated, CreatedDashboardTokenJSON{Token: dashboardTokenJSON(tok, now), Secret: secret})
}

func (a *api) revokeDashboardToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DashboardTokenRevoke, Target: "token/" + id,
	}, func(ctx context.Context) error { return a.store.DashboardTokens().Revoke(ctx, id, a.now()) })
	if err != nil {
		a.writeDashboardTokenError(w, r, "revoke dashboard token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeDashboardTokenError answers a failed token request of the admin.
func (a *api) writeDashboardTokenError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such dashboard token in use")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old",
			"the hub cluster's database predates dashboard tokens: run `hearth cluster migrate` first")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "dashboard token request failed")
	}
}

// bearerSecret is the request's bearer token, if it has one.
func bearerSecret(r *http.Request) (string, bool) {
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	secret = strings.TrimSpace(secret)
	return secret, ok && strings.EqualFold(scheme, "Bearer") && secret != ""
}

var errNoBearer = errors.New("no bearer token")

// dashboardSummary answers a dashboard's read. Only a dashboard token, as a
// bearer token, is a credential here: a session cookie is not.
func (a *api) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	ctx := policy.WithScope(r.Context(), policy.Read)
	now := a.now()
	tok, authErr := store.DashboardToken{}, errNoBearer
	if secret, ok := bearerSecret(r); ok {
		tok, authErr = a.store.DashboardTokens().Check(ctx, secret, now)
	}
	switch {
	case authErr == nil, errors.Is(authErr, errNoBearer), errors.Is(authErr, store.ErrNotFound),
		errors.Is(authErr, store.ErrTokenRevoked), errors.Is(authErr, store.ErrTokenExpired):
	default:
		a.log.ErrorContext(ctx, "check dashboard token", "err", authErr)
		writeError(w, http.StatusServiceUnavailable, "internal", "cannot check the token")
		return
	}
	actorID := "token/unknown"
	if tok.ID != "" {
		actorID = "token/" + tok.ID
	}
	req := policy.Request{
		ActorKind: policy.ActorDashboard, ActorID: actorID, Action: policy.DashboardRead, Target: "devices",
		Detail: map[string]any{"remote": remoteHost(r)},
	}

	decision := policy.Deny
	if authErr == nil {
		if ok, wait := a.dashboardReads.allow(tok.ID); !ok {
			writeRetry(w, http.StatusTooManyRequests, wait, "rate_limited", "too many reads; try again later")
			return
		}
		decision, _ = a.policy.Check(req)
	}
	if decision == policy.Allow {
		a.serveDashboardSummary(ctx, w, req, tok.ID, now)
		return
	}
	a.denyDashboardRead(ctx, req, authErr, decision, remoteHost(r), now)
	if authErr == nil {
		writeError(w, http.StatusForbidden, "forbidden", "dashboard reads are denied by policy")
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="hearth"`)
	writeError(w, http.StatusUnauthorized, "unauthenticated", "a valid dashboard token is required")
}

// serveDashboardSummary answers an allowed read. The first read of the hour
// goes through policy.Do and is audited; the others were decided by
// policy.Check alone and are counted for the next audit row.
func (a *api) serveDashboardSummary(ctx context.Context, w http.ResponseWriter, req policy.Request, id string, now time.Time) {
	key := "read/" + id
	due, quiet := a.dashboardAudit.due(key, now)
	if !due {
		out, err := a.dashboardSummaryOf(ctx)
		if err != nil {
			a.log.ErrorContext(ctx, "dashboard summary", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot read devices")
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	req.Detail["reads_unaudited"] = quiet
	var out DashboardSummaryJSON
	err := a.policy.Do(ctx, req, func(ctx context.Context) error {
		var err error
		out, err = a.dashboardSummaryOf(ctx)
		return err
	})
	switch {
	case err == nil:
		a.dashboardAudit.written(key, now)
		writeJSON(w, http.StatusOK, out)
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "dashboard reads are denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(ctx, "dashboard summary", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot read devices")
	}
}

// denyDashboardRead audits a refused read through policy, at most once per
// hour for each source and actor, with the count of refusals since. A read
// that would be held for approval is refused instead: a dashboard cannot
// wait for one.
func (a *api) denyDashboardRead(ctx context.Context, req policy.Request, authErr error, decision, remote string, now time.Time) {
	key := "deny/" + remote + "/" + req.ActorID
	due, quiet := a.dashboardAudit.due(key, now)
	if !due {
		return
	}
	var reason string
	switch {
	case errors.Is(authErr, errNoBearer):
		reason = "no dashboard token"
	case errors.Is(authErr, store.ErrNotFound):
		reason = "unknown dashboard token"
	case errors.Is(authErr, store.ErrTokenRevoked):
		reason = "dashboard token revoked"
	case errors.Is(authErr, store.ErrTokenExpired):
		reason = "dashboard token expired"
	case decision == policy.Confirm:
		reason = "a dashboard read cannot wait for approval"
	}
	req.Detail["denials_unaudited"] = quiet
	req.Precheck = func(context.Context) error {
		if reason == "" {
			return nil // the configuration denies it, and says why
		}
		return fmt.Errorf("%s: %w", reason, policy.ErrDenied)
	}
	// Precheck or the configuration refuses it: nothing runs.
	err := a.policy.Do(ctx, req, func(context.Context) error { return nil })
	if errors.Is(err, policy.ErrDenied) {
		a.dashboardAudit.written(key, now)
	}
}

// dashboardSummaryOf reads the summary from the store.
func (a *api) dashboardSummaryOf(ctx context.Context) (DashboardSummaryJSON, error) {
	devs, err := a.store.Devices().List(ctx)
	if err != nil {
		return DashboardSummaryJSON{}, fmt.Errorf("list devices: %w", err)
	}
	out := DashboardSummaryJSON{
		Version: dashboardSummaryVersion,
		Devices: make([]DashboardDeviceJSON, 0, min(len(devs), maxDashboardDevices)),
	}
	for _, d := range devs {
		d = a.registry.Live(d)
		out.Counts.Total++
		if d.Status == store.StatusOnline {
			out.Counts.Online++
		} else {
			out.Counts.Offline++
		}
		if len(out.Devices) == maxDashboardDevices {
			out.Truncated = true
			continue
		}
		dev := DashboardDeviceJSON{ID: d.ID, Name: d.Name, Status: d.Status}
		if !d.LastSeen.IsZero() {
			seen := d.LastSeen
			dev.LastSeen = &seen
		}
		out.Devices = append(out.Devices, dev)
	}
	return out, nil
}

// maxAuditThrottleKeys bounds the throttle's table; past it, keys whose
// hour is over are dropped, and if none is, all are.
const maxAuditThrottleKeys = 4096

// auditThrottle spaces the audit rows of a key out to one per every, and
// counts what happened in between. It lives in the hub process: a restart,
// or another hub of a cluster, starts its own count.
type auditThrottle struct {
	every time.Duration

	mu    sync.Mutex
	last  map[string]time.Time
	quiet map[string]int
}

func newAuditThrottle(every time.Duration) *auditThrottle {
	return &auditThrottle{every: every, last: map[string]time.Time{}, quiet: map[string]int{}}
}

// due reports whether key needs an audit row at now and, if it does, how
// many times it went without one since the last. A key that is not due has
// this time counted.
func (t *auditThrottle) due(key string, now time.Time) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if at, ok := t.last[key]; ok && now.Sub(at) < t.every {
		t.quiet[key]++
		return false, 0
	}
	return true, t.quiet[key]
}

// written records that key's audit row was written at now. Until then key
// stays due, so a failed write is tried again on the next request.
func (t *auditThrottle) written(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.last[key]; !ok && len(t.last) >= maxAuditThrottleKeys {
		for k, at := range t.last {
			if now.Sub(at) >= t.every {
				delete(t.last, k)
				delete(t.quiet, k)
			}
		}
		if len(t.last) >= maxAuditThrottleKeys {
			clear(t.last)
			clear(t.quiet)
		}
	}
	t.last[key] = now
	delete(t.quiet, key)
}
