// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/hub/webui"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// SessionCookie is the name of the admin session cookie.
	SessionCookie = "hearth_session"
	// SessionTTL is how long an admin session lasts.
	SessionTTL = 7 * 24 * time.Hour
	// sseKeepalive is how often an idle event stream gets a comment line,
	// and its session is re-checked.
	sseKeepalive = 25 * time.Second
	adminUser    = "admin"
	maxLoginBody = 4 << 10
)

// NewHTTPHandler serves the web UI at / and the JSON API at /api/v1 for the
// plain-HTTP listener. cfg.Registry must be the registry the agent handler
// reports to; if nil, a private one is created and /events stays silent.
func NewHTTPHandler(cfg Config) http.Handler {
	return newAPI(cfg).routes()
}

func newAPI(cfg Config) *api {
	reg := cfg.Registry
	if reg == nil {
		reg = NewRegistry(RegistryConfig{Store: cfg.Store, Log: cfg.Log})
	}
	agentPort := cfg.AgentPort
	if agentPort == "" {
		agentPort = DefaultAgentPort
	}
	return &api{
		store: cfg.Store, policy: cfg.Policy, registry: reg, log: cfg.Log, now: time.Now, keepalive: sseKeepalive,
		ca: cfg.CA, agentHosts: cfg.AgentHosts, agentPort: agentPort,
	}
}

func (a *api) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", webui.Handler())
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.Handle("POST /api/v1/logout", a.auth(a.logout))
	mux.Handle("GET /api/v1/session", a.auth(a.session))
	mux.Handle("GET /api/v1/devices", a.auth(a.listDevices))
	mux.Handle("GET /api/v1/devices/{id}", a.auth(a.getDevice))
	mux.Handle("GET /api/v1/events", a.auth(a.events))
	mux.Handle("POST /api/v1/tokens", a.auth(a.createToken))
	mux.Handle("/api/v1/", a.auth(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
	}))
	return mux
}

type api struct {
	store      *store.Store
	ca         *pki.CA
	agentHosts []string
	agentPort  string
	policy     *policy.Engine
	registry   *Registry
	log        *slog.Logger
	now        func() time.Time
	keepalive  time.Duration
	// verifyMu runs one argon2 verification at a time, so a flood of login
	// attempts cannot exhaust a small hub's memory.
	verifyMu sync.Mutex
}

// DeviceJSON is the API representation of a device.
type DeviceJSON struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Hostname  string            `json:"hostname"`
	OS        string            `json:"os"`
	Arch      string            `json:"arch"`
	Status    string            `json:"status"`
	Labels    map[string]string `json:"labels"`
	Facts     json.RawMessage   `json:"facts"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

func deviceJSON(d store.Device) DeviceJSON {
	labels := d.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	facts := d.Facts
	if len(facts) == 0 {
		facts = json.RawMessage(`{}`)
	}
	return DeviceJSON{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, OS: d.OS, Arch: d.Arch, Status: d.Status,
		Labels: labels, Facts: facts, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen,
	}
}

// SessionJSON is the body of a successful login and of GET /session.
type SessionJSON struct {
	User      string    `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ErrorJSON is the body of every API error.
type ErrorJSON struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

var (
	errPasswordNotSet = errors.New("admin password not set")
	errWrongPassword  = errors.New("wrong password")
)

func (a *api) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {\"password\": \"...\"}")
		return
	}

	secret, err := newSessionSecret()
	if err != nil {
		a.log.ErrorContext(ctx, "login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "login failed")
		return
	}
	now := a.now()
	expires := now.Add(SessionTTL).UTC().Truncate(time.Millisecond) // as stored and served by /session
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb,
		ActorID:   remoteHost(r),
		Action:    policy.AdminLogin,
		Target:    adminUser,
	}, func(ctx context.Context) error {
		hash, err := a.store.Admin().PasswordHash(ctx)
		if errors.Is(err, store.ErrNotFound) {
			return errPasswordNotSet
		}
		if err != nil {
			return err
		}
		a.verifyMu.Lock()
		ok, err := verifyPassword(hash, body.Password)
		a.verifyMu.Unlock()
		if err != nil {
			return err
		}
		if !ok {
			return errWrongPassword
		}
		return a.store.Admin().CreateSession(ctx, secret, now, expires)
	})
	switch {
	case errors.Is(err, errWrongPassword):
		a.log.WarnContext(ctx, "admin login failed", "remote", remoteHost(r))
		writeError(w, http.StatusUnauthorized, "bad_credentials", "wrong password")
		return
	case errors.Is(err, errPasswordNotSet):
		writeError(w, http.StatusServiceUnavailable, "password_not_set",
			"admin password not set: run `hearth admin set-password` on the hub host")
		return
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "login denied by policy")
		return
	case err != nil:
		a.log.ErrorContext(ctx, "admin login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "login failed")
		return
	}

	a.log.InfoContext(ctx, "admin logged in", "remote", remoteHost(r))
	// Not Secure: the API is served over plain HTTP on the LAN (see D1).
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // HttpOnly and SameSite=Strict are set; Secure cannot be over plain HTTP
		Name:     SessionCookie,
		Value:    secret,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, SessionJSON{User: adminUser, ExpiresAt: expires})
}

func (a *api) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		if err := a.store.Admin().DeleteSession(r.Context(), c.Value); err != nil {
			a.log.ErrorContext(r.Context(), "logout", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "logout failed")
			return
		}
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // clears the cookie; see login
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) session(w http.ResponseWriter, r *http.Request) {
	exp, _ := r.Context().Value(sessionExpiryKey{}).(time.Time)
	writeJSON(w, http.StatusOK, SessionJSON{User: adminUser, ExpiresAt: exp})
}

func (a *api) listDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := a.store.Devices().List(r.Context())
	if err != nil {
		a.log.ErrorContext(r.Context(), "list devices", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot list devices")
		return
	}
	out := struct {
		Devices []DeviceJSON `json:"devices"`
	}{Devices: make([]DeviceJSON, 0, len(devs))}
	for _, d := range devs {
		out.Devices = append(out.Devices, deviceJSON(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) getDevice(w http.ResponseWriter, r *http.Request) {
	d, err := a.store.Devices().Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		a.log.ErrorContext(r.Context(), "get device", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot get device")
		return
	}
	writeJSON(w, http.StatusOK, deviceJSON(d))
}

// EventJSON is the data of one server-sent event; the SSE event name is Type.
type EventJSON struct {
	Type   string     `json:"type"`
	Device DeviceJSON `json:"device"`
}

// events streams registry events as server-sent events until the client goes
// away, its session ends, or it falls too far behind (it should then refetch
// /devices and reconnect, which EventSource does by itself).
func (a *api) events(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rc := http.NewResponseController(w)
	ch, unsubscribe := a.registry.Subscribe()
	defer unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// The comment tells the client the subscription is live.
	if _, err := fmt.Fprint(w, ": subscribed\n\n"); err != nil || rc.Flush() != nil {
		return
	}

	keepalive := time.NewTicker(a.keepalive)
	defer keepalive.Stop()
	for {
		var err error
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, mErr := json.Marshal(EventJSON{Type: ev.Type, Device: deviceJSON(ev.Device)})
			if mErr != nil {
				a.log.ErrorContext(ctx, "encode event", "err", mErr)
				continue
			}
			_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
		case <-keepalive.C:
			if _, err := a.checkSession(r); err != nil {
				return
			}
			_, err = fmt.Fprint(w, ": keepalive\n\n")
		}
		if err != nil || rc.Flush() != nil {
			return
		}
	}
}

type sessionExpiryKey struct{}

// auth admits only requests with a valid session cookie.
func (a *api) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exp, err := a.checkSession(r)
		switch {
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrSessionExpired), errors.Is(err, http.ErrNoCookie):
			writeError(w, http.StatusUnauthorized, "unauthenticated", "not logged in")
			return
		case err != nil:
			a.log.ErrorContext(r.Context(), "check session", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot check session")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionExpiryKey{}, exp)))
	})
}

func (a *api) checkSession(r *http.Request) (time.Time, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return time.Time{}, err
	}
	if c.Value == "" {
		return time.Time{}, store.ErrNotFound
	}
	return a.store.Admin().CheckSession(r.Context(), c.Value, a.now())
}

func newSessionSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("new session secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// remoteHost is the peer address. Forwarding headers are not trusted.
func remoteHost(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, ErrorJSON{Error: msg, Code: code})
}
