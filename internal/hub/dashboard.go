// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
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
// allowed read of each token and source per hour, not every read, and the
// first denied read per token and source, or per reason for an unknown
// token, per hour. Each row counts the reads (or denials) since the
// previous one, and DashboardAudit.Run flushes waiting counts every
// DashboardFlushEvery.

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
	// maxDashboardTokenID bounds a token ID in a revoke request.
	maxDashboardTokenID = 64
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
	// IDs are 26 characters; anything much longer names no token, and is
	// kept out of the audit log.
	if len(id) > maxDashboardTokenID {
		writeError(w, http.StatusNotFound, "not_found", "no such dashboard token in use")
		return
	}
	ctx, reach := store.WithReach(r.Context())
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DashboardTokenRevoke, Target: "token/" + id,
	}, func(ctx context.Context) error { return a.store.DashboardTokens().Revoke(ctx, id, a.now()) })
	if err != nil {
		a.writeDashboardTokenError(w, r, "revoke dashboard token", err)
		return
	}
	writeReach(w, *reach)
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
			"the hub cluster's database predates dashboard tokens: upgrade every hub of the cluster first")
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

// dashboardSummary answers a dashboard's read. Only a dashboard token, as a
// bearer token, is a credential here: a session cookie is not.
func (a *api) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	ctx := policy.WithScope(r.Context(), policy.Read)
	now := a.now()
	remote := remoteHost(r)
	tok, reason := store.DashboardToken{}, "no dashboard token"
	if secret, ok := bearerSecret(r); ok {
		var err error
		tok, err = a.store.DashboardTokens().Check(ctx, secret, now)
		switch {
		case err == nil:
			reason = ""
		case errors.Is(err, store.ErrNotFound):
			reason = "unknown dashboard token"
		case errors.Is(err, store.ErrTokenRevoked):
			reason = "dashboard token revoked"
		case errors.Is(err, store.ErrTokenExpired):
			reason = "dashboard token expired"
		case errors.Is(err, store.ErrUnavailable):
			// A master still comparing tokens with the others (#384).
			writeUnavailable(w)
			return
		default:
			a.log.ErrorContext(ctx, "check dashboard token", "err", err)
			writeError(w, http.StatusServiceUnavailable, "internal", "cannot check the token")
			return
		}
	} else if r.Header.Get("Authorization") != "" {
		reason = "not a bearer token"
	}
	actorID := "token/unknown"
	if tok.ID != "" {
		actorID = "token/" + tok.ID
	}
	req := policy.Request{
		ActorKind: policy.ActorDashboard, ActorID: actorID, Action: policy.DashboardRead, Target: "devices",
		Detail: map[string]any{"remote": remote},
	}

	if reason == "" {
		key := "read/" + tok.ID + "/" + remote
		if ok, wait := a.dashboardReads.allow(tok.ID); !ok {
			a.dashboardAudit.count(key, req, "")
			writeRetry(w, http.StatusTooManyRequests, wait, "rate_limited", "too many reads; try again later")
			return
		}
		if d, _ := a.policy.Check(req); d == policy.Allow {
			a.serveDashboardSummary(ctx, w, key, req, now)
			return
		}
	}
	// A known token is throttled per source; an unknown one per reason, so
	// that no stream of sources or secrets adds rows.
	key := "deny/" + actorID + "/" + reason
	if tok.ID != "" {
		key += "/" + remote
	}
	a.denyDashboardRead(ctx, key, req, reason, now)
	if reason == "" {
		writeError(w, http.StatusForbidden, "forbidden", "dashboard reads are denied by policy")
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="hearth"`)
	writeError(w, http.StatusUnauthorized, "unauthenticated", "a valid dashboard token is required")
}

// dashboardPrecheck refuses a dashboard read for reason, when it has one,
// and refuses one the configuration would hold for approval: a dashboard
// cannot wait for one.
func dashboardPrecheck(e *policy.Engine, req policy.Request, reason string) func(context.Context) error {
	return func(context.Context) error {
		if reason != "" {
			return fmt.Errorf("%s: %w", reason, policy.ErrDenied)
		}
		if d, _ := e.Check(req); d == policy.Confirm {
			return fmt.Errorf("a dashboard read cannot wait for approval: %w", policy.ErrDenied)
		}
		return nil
	}
}

// serveDashboardSummary answers an allowed read. The first read of the hour
// from each token and source goes through policy.Do and is audited; the
// others were decided by policy.Check alone and are counted for the next
// audit row.
func (a *api) serveDashboardSummary(ctx context.Context, w http.ResponseWriter, key string, req policy.Request, now time.Time) {
	due, quiet := a.dashboardAudit.due(key, now, req, "")
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
	req.Detail[readsUnaudited] = quiet
	req.Precheck = dashboardPrecheck(a.policy, req, "")
	var out DashboardSummaryJSON
	err := a.policy.Do(ctx, req, func(ctx context.Context) error {
		var err error
		out, err = a.dashboardSummaryOf(ctx)
		return err
	})
	switch {
	case err == nil:
		a.dashboardAudit.written(key, now, quiet)
		writeJSON(w, http.StatusOK, out)
	case errors.Is(err, policy.ErrDenied):
		a.dashboardAudit.written(key, now, quiet)
		writeError(w, http.StatusForbidden, "forbidden", "dashboard reads are denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(ctx, "dashboard summary", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot read devices")
	}
}

// denyDashboardRead audits a refused read through policy, at most once an
// hour for key, with the count of refusals since.
func (a *api) denyDashboardRead(ctx context.Context, key string, req policy.Request, reason string, now time.Time) {
	due, quiet := a.dashboardAudit.due(key, now, req, reason)
	if !due {
		return
	}
	req.Detail[denialsUnaudited] = quiet
	req.Precheck = dashboardPrecheck(a.policy, req, reason)
	// Precheck or the configuration refuses it: nothing runs.
	if err := a.policy.Do(ctx, req, func(context.Context) error { return nil }); errors.Is(err, policy.ErrDenied) {
		a.dashboardAudit.written(key, now, quiet)
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

// Detail keys of the counts an audit row of dashboard reads carries.
const (
	readsUnaudited   = "reads_unaudited"
	denialsUnaudited = "denials_unaudited"
)

const (
	// DashboardFlushEvery is how often DashboardAudit.Run writes the counts
	// of reads and refusals that are waiting for their next audit row.
	DashboardFlushEvery = 10 * time.Minute
	// maxDashboardAuditKeys bounds the throttle's table; past it, a new key
	// gets an audit row every time.
	maxDashboardAuditKeys = 4096
	// dashboardFlushTimeout bounds the last flush when the hub stops.
	dashboardFlushTimeout = 10 * time.Second
)

// DashboardAudit spaces out the audit rows of dashboard reads: one per key
// every dashboardAuditEvery, each counting the reads (or refusals) since the
// previous one, and a flush every DashboardFlushEvery for counts still
// waiting. Counts not yet flushed live in the hub process and are lost if it
// dies; a hub that stops cleanly flushes them first (see Run).
type DashboardAudit struct {
	policy *policy.Engine
	log    *slog.Logger
	every  time.Duration

	mu   sync.Mutex
	keys map[string]*dashboardAuditKey
}

// dashboardAuditKey is one throttled key: when its last row was written,
// what happened since, and its latest request, for a flush.
type dashboardAuditKey struct {
	last   time.Time
	quiet  int
	req    policy.Request
	reason string
}

// NewDashboardAudit returns the throttle of dashboard reads' audit rows,
// whose flushes are decided and audited by pol. Run it, and pass it to the
// API in Config.DashboardAudit.
func NewDashboardAudit(pol *policy.Engine, log *slog.Logger) *DashboardAudit {
	return &DashboardAudit{policy: pol, log: log, every: dashboardAuditEvery, keys: map[string]*dashboardAuditKey{}}
}

// due reports whether key needs an audit row at now and, if it does, how
// many times it went without one since the last. A key that is not due has
// this time counted. req is kept as the key's latest request.
func (d *DashboardAudit) due(key string, now time.Time, req policy.Request, reason string) (bool, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := d.key(key, now)
	if k == nil {
		return true, 0
	}
	k.req, k.reason = req, reason
	if !k.last.IsZero() && now.Sub(k.last) < d.every {
		k.quiet++
		return false, 0
	}
	return true, k.quiet
}

// count counts a time key went without an audit row, such as a read
// refused for its rate.
func (d *DashboardAudit) count(key string, req policy.Request, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if k := d.key(key, time.Time{}); k != nil {
		k.req, k.reason = req, reason
		k.quiet++
	}
}

// written records that key's audit row, counting n, was written at now.
// Until then key stays due, so a failed write is tried again.
func (d *DashboardAudit) written(key string, now time.Time, n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if k, ok := d.keys[key]; ok {
		k.last = now
		k.quiet = max(0, k.quiet-n)
	}
}

// key returns key's entry, made if new; nil when the table is full of keys
// that still count something.
func (d *DashboardAudit) key(key string, now time.Time) *dashboardAuditKey {
	if k, ok := d.keys[key]; ok {
		return k
	}
	if len(d.keys) >= maxDashboardAuditKeys {
		for name, k := range d.keys {
			if k.quiet == 0 && (now.IsZero() || now.Sub(k.last) >= d.every) {
				delete(d.keys, name)
			}
		}
		if len(d.keys) >= maxDashboardAuditKeys {
			return nil
		}
	}
	k := &dashboardAuditKey{}
	d.keys[key] = k
	return k
}

// Run flushes the waiting counts every DashboardFlushEvery until ctx ends,
// and once more as the hub stops.
func (d *DashboardAudit) Run(ctx context.Context) error {
	t := time.NewTicker(DashboardFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dashboardFlushTimeout)
			d.flush(fctx, time.Now())
			cancel()
			return nil
		case <-t.C:
			d.flush(ctx, time.Now())
		}
	}
}

// flush writes an audit row for every key with counts waiting: the key's
// latest request, decided again, with the count and "flush": true.
func (d *DashboardAudit) flush(ctx context.Context, now time.Time) {
	type pending struct {
		key    string
		req    policy.Request
		reason string
		n      int
	}
	d.mu.Lock()
	var todo []pending
	for name, k := range d.keys {
		if k.quiet > 0 {
			todo = append(todo, pending{name, k.req, k.reason, k.quiet})
		}
	}
	d.mu.Unlock()
	for _, p := range todo {
		req := p.req
		req.Detail = maps.Clone(req.Detail)
		if req.Detail == nil {
			req.Detail = map[string]any{}
		}
		countKey := readsUnaudited
		if strings.HasPrefix(p.key, "deny/") {
			countKey = denialsUnaudited
		}
		req.Detail[countKey], req.Detail["flush"] = p.n, true
		req.Precheck = dashboardPrecheck(d.policy, req, p.reason)
		err := d.policy.Do(policy.WithScope(ctx, policy.Read), req, func(context.Context) error { return nil })
		if err == nil || errors.Is(err, policy.ErrDenied) {
			d.written(p.key, now, p.n)
			continue
		}
		if ctx.Err() != nil {
			return
		}
		d.log.WarnContext(ctx, "flush dashboard read counts", "actor", req.ActorID, "err", err)
	}
}
