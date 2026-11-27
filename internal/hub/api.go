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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/hub/webui"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/integrations/esphome"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/integrations/proxmox"
	"github.com/gvart/hearth/internal/metrics"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// SessionCookie is the name of the admin session cookie over plain HTTP.
	SessionCookie = "hearth_session"
	// SecureSessionCookie is its name over HTTPS. Cookies ignore ports and,
	// unless Secure, schemes, so one name for both would let the HTTP login
	// collide with the Secure HTTPS one (browsers refuse to overwrite a Secure
	// cookie from HTTP). Each scheme therefore keeps its own session.
	SecureSessionCookie = "__Host-hearth_session"
	// SessionTTL is how long an admin session lasts.
	SessionTTL = 7 * 24 * time.Hour
	// sseKeepalive is how often an idle event stream gets a comment line,
	// and its session is re-checked.
	sseKeepalive = 25 * time.Second
	adminUser    = "admin"
	maxLoginBody = 4 << 10
)

// NewHTTPHandler serves the web UI at / and the JSON API at /api/v1, over plain
// HTTP or, behind NewTLSHandler, HTTPS. cfg.Registry must be the registry the agent handler
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
	httpPort := cfg.HTTPPort
	if httpPort == "" {
		httpPort = DefaultHTTPPort
	}
	verifier := cfg.VerifyPassword
	if verifier == nil {
		verifier = verifyInProcess
	}
	a := &api{
		store: cfg.Store, policy: cfg.Policy, registry: reg, log: cfg.Log, now: time.Now, keepalive: sseKeepalive,
		ca: cfg.CA, agentHosts: cfg.AgentHosts, agentPort: agentPort, httpPort: httpPort, ready: cfg.Ready, readyWait: readyWait,
		prom:     cfg.Prometheus,
		netEdges: cfg.NetEdges,
		beszel:   cfg.Beszel,
		talos:    cfg.Talos,
		kube:     cfg.Kube,
		proxmox:  cfg.Proxmox,
		esphome:  cfg.ESPHome,
		plugins:  cfg.Plugins,
		notify:   cfg.Notify,
		verify:   newVerifyGate(), verifyWait: verifyWait, verifyPassword: verifier,
		logins:           newLoginLimiter(time.Now, loginBurst, loginEvery),
		metrics:          cfg.Metrics,
		drift:            cfg.ConfigDrift,
		runbooks:         cfg.Runbooks,
		leadership:       leadershipOf(cfg),
		masters:          cfg.Masters,
		clusterAdmin:     cfg.ClusterAdmin,
		clusterCA:        cfg.ClusterCA,
		automations:      automation.Files{Dir: cfg.AutomationsDir, Docs: cfg.AutomationDocs, Kinds: cfg.AutomationKinds},
		automationsMu:    automationsLock(cfg.AutomationsLock),
		agents:           cfg.Agents,
		scans:            cfg.NetworkScans,
		discoverInterval: cfg.DiscoverInterval,
		dryRuns:          newLoginLimiter(time.Now, dryRunBurst, dryRunEvery),
		// Only a release tag is pinned: dev builds have no release to install.
		installVersion: releaseVersion(cfg.Version),
		version:        cfg.Version,
		argon:          defaultArgon,
		configSealer:   cfg.ConfigSealer,
		configKinds:    cfg.ConfigKinds,
		backup:         cfg.Backup,
		backupDir:      cfg.BackupDir,
		telemetryOff:   cfg.TelemetryOff,
		shellIdle:      orDefault(cfg.ShellIdleTimeout, DefaultShellIdleTimeout),
		shellMax:       orDefault(cfg.ShellMaxDuration, DefaultShellMaxDuration),
		runner:         runnerOf(cfg.Agents),
		guestActions:   newLoginLimiter(time.Now, guestActionBurst, guestActionEvery),
	}
	now := func() time.Time { return a.now() }
	a.guestActions = newLoginLimiter(now, guestActionBurst, guestActionEvery)
	a.guestReads = newLoginLimiter(now, guestReadBurst, guestReadEvery)
	a.dashboardReads = newLoginLimiter(now, dashboardReadBurst, dashboardReadEvery)
	a.dashboardAudit = cfg.DashboardAudit
	if a.dashboardAudit == nil {
		a.dashboardAudit = NewDashboardAudit(cfg.Policy, cfg.Log)
	}
	a.hubs, _ = cfg.Masters.(hubCounter)
	a.members, _ = cfg.Masters.(memberLister)
	return a
}

// runnerOf is agents as an agentRunner, nil when there are none.
func runnerOf(agents *Agents) agentRunner {
	if agents == nil {
		return nil
	}
	return agents
}

func (a *api) routes() http.Handler {
	mux := http.NewServeMux()
	ui := webui.Handler()
	mux.Handle("/", ui)
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("GET /api/v1/tls", a.tlsInfo)
	mux.Handle("POST /api/v1/logout", a.auth(a.logout))
	mux.Handle("GET /api/v1/session", a.auth(a.session))
	mux.Handle("POST /api/v1/session/reauth", a.auth(a.reauth))
	mux.Handle("GET /api/v1/devices", a.auth(a.listDevices))
	mux.Handle("GET /api/v1/devices/{id}", a.auth(a.getDevice))
	mux.Handle("GET /api/v1/devices/{id}/metrics", a.auth(a.deviceMetrics))
	mux.Handle("GET /api/v1/devices/{id}/hub", a.auth(a.deviceHub))
	mux.Handle("POST /api/v1/devices/{id}/hub", a.auth(a.makeDeviceHub))
	mux.Handle("POST /api/v1/devices/{id}/upgrade", a.auth(a.upgradeDevice))
	mux.Handle("GET /api/v1/metrics/sparklines", a.auth(a.metricsSparklines))
	mux.Handle("GET /api/v1/network/hosts", a.auth(a.listNetworkHosts))
	mux.Handle("GET /api/v1/beszel/systems", a.auth(a.listBeszelSystems))
	mux.Handle("GET /api/v1/talos/nodes", a.auth(a.listTalosNodes))
	mux.Handle("POST /api/v1/network/hosts/{mac}/known", a.auth(a.markNetworkHost(store.HostKnown)))
	mux.Handle("POST /api/v1/network/hosts/{mac}/ignore", a.auth(a.markNetworkHost(store.HostIgnored)))
	mux.Handle("POST /api/v1/network/hosts/{mac}/unmark", a.auth(a.markNetworkHost(store.HostUnreviewed)))
	mux.Handle("POST /api/v1/network/hosts/{mac}/adopt", a.auth(a.adoptNetworkHost(true)))
	mux.Handle("POST /api/v1/network/hosts/{mac}/unadopt", a.auth(a.adoptNetworkHost(false)))
	mux.Handle("POST /api/v1/network/scan", a.auth(a.scanNetwork))
	mux.Handle("GET /api/v1/events", a.auth(a.events))
	mux.Handle("POST /api/v1/tokens", a.auth(a.createToken))
	mux.Handle("GET /api/v1/tokens", a.auth(a.listTokens))
	mux.Handle("DELETE /api/v1/tokens/{id}", a.auth(a.revokeToken))
	a.kubeRoutes(mux)
	a.proxmoxRoutes(mux)
	a.esphomeRoutes(mux)
	a.pluginRoutes(mux)
	a.notifyRoutes(mux)
	a.automationRoutes(mux)
	mux.Handle("GET /api/v1/cluster/config-drift", a.auth(a.configDrift))
	a.clusterRoutes(mux)
	a.clusterCARoutes(mux)
	a.logRoutes(mux)
	a.shellRoutes(mux)
	mux.Handle("GET /api/v1/audit", a.auth(a.listAudit))
	mux.Handle("GET /api/v1/approvals", a.auth(a.listApprovals))
	mux.Handle("POST /api/v1/approvals/{id}/approve", a.auth(a.decideApproval(true)))
	mux.Handle("POST /api/v1/approvals/{id}/deny", a.auth(a.decideApproval(false)))
	a.approvalLinkRoutes(mux)
	a.runbookRoutes(mux)
	a.telemetryRoutes(mux)
	a.netEdgeRoutes(mux)
	a.dockerRoutes(mux)
	a.panelRoutes(mux)
	a.guestRoutes(mux, ui)
	a.dashboardRoutes(mux)
	a.webAdminRoutes(mux)
	a.capabilitiesRoutes(mux)
	a.configEditRoutes(mux)
	a.backupRoutes(mux)
	mux.Handle("/api/v1/", a.auth(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
	}))
	if a.ready == nil {
		return mux
	}
	return a.whenReady(mux)
}

// readyWait is how long an API request on a clustered hub that is still
// catching up waits before it is answered 503 catching_up.
const readyWait = 5 * time.Second

// whenReady holds JSON API requests until the hub has caught up with the
// cluster (a.ready is closed), for at most a.readyWait. The UI's static files
// are served at once.
func (a *api) whenReady(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			t := time.NewTimer(a.readyWait)
			defer t.Stop()
			select {
			case <-a.ready:
			case <-r.Context().Done():
				return
			case <-t.C:
				writeError(w, http.StatusServiceUnavailable, "catching_up",
					"this hub is catching up with the cluster; try again shortly")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type api struct {
	store      *store.Store
	ca         *pki.CA
	agentHosts []string
	agentPort  string
	httpPort   string
	policy     *policy.Engine
	registry   *Registry
	log        *slog.Logger
	now        func() time.Time
	keepalive  time.Duration
	// ready is Config.Ready; requests wait for it up to readyWait.
	ready     <-chan struct{}
	readyWait time.Duration
	// verify runs one argon2 verification at a time, so a flood of login
	// attempts can neither exhaust a small hub's memory nor starve the cluster.
	verify         verifyGate
	verifyWait     time.Duration
	verifyPassword PasswordVerifier
	// logins rate-limits login attempts per client address.
	logins *loginLimiter
	// prom is Config.Prometheus; nil when no Prometheus is configured.
	prom *prometheus.Reader
	// beszel is Config.Beszel; nil when no Beszel is configured.
	beszel BeszelSnapshotter
	// talos is Config.Talos; nil when no talosconfig is configured.
	talos TalosSnapshotter
	// metrics is Config.Metrics; nil when the hub keeps no metrics.
	metrics *metrics.Store
	// netEdges serves the network edges agents report; nil serves none.
	netEdges *NetEdges
	// kube is Config.Kube; nil when Kubernetes clusters are not served.
	kube *kubernetes.Manager
	// proxmox is Config.Proxmox; nil when Proxmox servers are not served.
	proxmox *proxmox.Manager
	// esphome is Config.ESPHome; nil when ESPHome devices are not served.
	esphome *esphome.Manager
	// plugins is Config.Plugins; nil when no exec plugin is configured.
	plugins *plugins.Manager
	// notify is Config.Notify; nil when notification channels are not served.
	notify *notify.Notifier
	// drift is Config.ConfigDrift; nil on a standalone hub.
	drift func(context.Context) (any, error)
	// runbooks is Config.Runbooks; nil when runbooks are not served.
	runbooks *automation.Runbooks
	// leadership names the cluster's leader, where secret answers must go.
	leadership Leadership
	// clusterAdmin is Config.ClusterAdmin; nil outside an AP cluster.
	clusterAdmin ClusterAdmin
	// clusterCA is Config.ClusterCA; nil outside an AP cluster.
	clusterCA ClusterCA
	// masters is Config.Masters; nil outside an AP cluster.
	masters Masters
	// hubs and members are masters, when it counts and lists the members:
	// a device's hub (devicehub.go). hubMintMu serializes counting and
	// minting a device's join token.
	hubs      hubCounter
	members   memberLister
	hubMintMu sync.Mutex
	// capsMu makes each change of a device's capabilities one step: its
	// read, decision and write (capabilities.go).
	capsMu sync.Mutex
	// automations are the files the automation editor reads and writes.
	automations automation.Files
	// automationsMu makes each save's check and write one step.
	automationsMu sync.Locker
	// dryRuns limits how often a client may ask for a dry run.
	dryRuns *loginLimiter
	// agents is Config.Agents; nil when device logs and terminals are not served.
	agents *Agents
	// scans is Config.NetworkScans; nil when scans cannot be asked for.
	scans *NetworkScans
	// discoverInterval is Config.DiscoverInterval (zero: discovery's default):
	// a network host is online if seen within twice of it.
	discoverInterval time.Duration
	// installVersion is the --version install commands pin, or "" for none.
	installVersion string
	// version is the hub's build version, shown by the web UI.
	version string
	// reauths are the sessions that entered the password again lately.
	reauths reauths
	// argon is the cost of a password the web UI sets.
	argon argonParams
	// configSealer and configKinds are Config's: nil without the editors of
	// configuration documents.
	configSealer hubconfig.Sealer
	configKinds  func(*notify.Notifier) automation.Kinds
	// configMu makes each write of configuration documents from this hub's
	// web UI one step: its check and its write.
	configMu sync.Mutex
	// backup and backupDir are Config's; nil without backup downloads.
	backup    func(ctx context.Context, output, passphrase string) error
	backupDir string
	// telemetryOff is Config.TelemetryOff.
	telemetryOff bool
	// shellIdle and shellMax limit terminal sessions.
	shellIdle, shellMax time.Duration
	// runner is agents as an agentRunner, for guest actions; nil when the
	// hub runs no agent actions.
	runner agentRunner
	// guestActions limits the actions of each panel share link.
	guestActions *loginLimiter
	// guestReads limits the panel reads of each panel share link.
	guestReads *loginLimiter
	// guestBusy bounds each share link's actions running at once, and
	// guestHeld those held for approval.
	guestBusy, guestHeld guestInflight
	// guestStreams counts the guest event streams and wakes them.
	guestStreams guestStreams
	// dashboardReads limits the reads of each dashboard token.
	dashboardReads *loginLimiter
	// dashboardAudit spaces out the audit rows of dashboard reads.
	dashboardAudit *DashboardAudit
}

// orDefault is d, or def when d is not positive.
func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
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
	// BootTime is when the host last booted, derived from heartbeat uptime;
	// null until the first heartbeat that reports uptime.
	BootTime *time.Time `json:"boot_time"`
	// AgentVersion is the agent's version next to the hub's, and whether it
	// can be upgraded from the hub; absent for a device without an agent
	// that reported one.
	AgentVersion *AgentVersionJSON `json:"agent_version,omitempty"`
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
	var boot *time.Time
	if !d.BootTime.IsZero() {
		boot = &d.BootTime
	}
	return DeviceJSON{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, OS: d.OS, Arch: d.Arch, Status: d.Status,
		Labels: labels, Facts: facts, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, BootTime: boot,
	}
}

// SessionJSON is the body of a successful login and of GET /session.
type SessionJSON struct {
	User      string    `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
	// ReauthUntil is when the session's last entry of the password stops
	// covering sensitive actions; absent when none is in force.
	ReauthUntil *time.Time `json:"reauth_until,omitempty"`
	// Version is the hub's build version.
	Version string `json:"version"`
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
	if ok, wait := a.logins.allow(remoteHost(r)); !ok {
		writeRetry(w, http.StatusTooManyRequests, wait, "rate_limited", "too many login attempts; try again later")
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
		if err := a.checkAdminPassword(ctx, body.Password); err != nil {
			return err
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
	case errors.Is(err, errVerifyBusy):
		writeRetry(w, http.StatusServiceUnavailable, a.verifyWait, "busy", "the hub is busy with other logins; try again shortly")
		return
	case ctx.Err() != nil:
		return // the client went away
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
		return
	case err != nil:
		a.log.ErrorContext(ctx, "admin login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "login failed")
		return
	}

	a.log.InfoContext(ctx, "admin logged in", "remote", remoteHost(r))
	// The password was just entered: it covers sensitive actions for a while.
	until := a.reauths.mark(secret, now).UTC()
	// Secure whenever the request came over TLS; over plain HTTP on the LAN
	// it cannot be (see D1).
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // HttpOnly and SameSite=Strict are set; Secure is set over TLS
		Name:     sessionCookieName(r),
		Value:    secret,
		Path:     "/",
		Expires:  expires,
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, SessionJSON{User: adminUser, ExpiresAt: expires, ReauthUntil: &until, Version: a.version})
}

// checkAdminPassword checks password against the admin password, as login
// and approving do: one argon2 verification at a time (see a.verify). It
// returns nil on a match, errWrongPassword, errPasswordNotSet, errVerifyBusy,
// or another error that never holds the password.
func (a *api) checkAdminPassword(ctx context.Context, password string) error {
	hash, err := a.store.Admin().PasswordHash(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return errPasswordNotSet
	}
	if err != nil {
		return err
	}
	var ok bool
	var verr error
	if err := a.verify.do(ctx, a.verifyWait, func() { ok, verr = a.verifyPassword(ctx, hash, password) }); err != nil {
		return err
	}
	if verr != nil {
		return verr
	}
	if !ok {
		return errWrongPassword
	}
	return nil
}

func (a *api) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName(r)); err == nil {
		a.reauths.forget(c.Value)
		if err := a.store.Admin().DeleteSession(r.Context(), c.Value); errors.Is(err, store.ErrUnavailable) {
			writeUnavailable(w)
			return
		} else if err != nil {
			a.log.ErrorContext(r.Context(), "logout", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "logout failed")
			return
		}
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // clears the cookie; see login
		Name: sessionCookieName(r), Value: "", Path: "/", MaxAge: -1,
		Secure: r.TLS != nil, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) session(w http.ResponseWriter, r *http.Request) {
	exp, _ := r.Context().Value(sessionExpiryKey{}).(time.Time)
	out := SessionJSON{User: adminUser, ExpiresAt: exp, Version: a.version}
	if until := a.reauthUntil(r); !until.IsZero() {
		until = until.UTC()
		out.ReauthUntil = &until
	}
	writeJSON(w, http.StatusOK, out)
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
		out.Devices = append(out.Devices, a.deviceJSON(d))
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
	out := a.deviceJSON(d)
	if v := out.AgentVersion; v != nil && !v.RemoteUpgrade && v.NoRemoteUpgrade == "" {
		// An agent older than remote upgrades: the installer's command
		// upgrades it once (#347).
		if httpHost, _, ok := a.commandHosts(r.Host, r.TLS != nil); ok {
			v.InstallCommand = a.installCommandWith(httpHost, "")
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// EventJSON is the data of one server-sent event; the SSE event name is Type.
type EventJSON struct {
	Type   string     `json:"type"`
	Device DeviceJSON `json:"device"`
}

// NetworkEventJSON is the data of a network discovery event.
type NetworkEventJSON struct {
	Type string          `json:"type"`
	Host NetworkHostJSON `json:"host"`
}

// events streams registry events, and Kubernetes notices when a.kube is
// set, as server-sent events until the client goes away, its session ends,
// or it falls too far behind (it should then refetch /devices and the
// clusters and reconnect, which EventSource does by itself).
func (a *api) events(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rc := http.NewResponseController(w)
	ch, unsubscribe := a.registry.SubscribeUI()
	defer unsubscribe()
	var kubeCh <-chan kubernetes.Notice // nil, never ready, without a.kube
	if a.kube != nil {
		var unsubscribeKube func()
		kubeCh, unsubscribeKube = a.kube.Subscribe()
		defer unsubscribeKube()
	}

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
			// Clients get one message per host of a network discovery event.
			bodies := []any{EventJSON{Type: ev.Type, Device: a.deviceJSON(ev.Device)}}
			switch {
			case ev.Scan != nil:
				bodies = []any{ev.Scan}
			case ev.Hosts != nil:
				bodies = bodies[:0]
				for _, h := range ev.Hosts {
					bodies = append(bodies, NetworkEventJSON{Type: ev.Type, Host: a.networkHostJSON(h, "")})
				}
			}
			for _, body := range bodies {
				data, mErr := json.Marshal(body)
				if mErr != nil {
					a.log.ErrorContext(ctx, "encode event", "err", mErr)
					continue
				}
				if _, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data); err != nil {
					break
				}
			}
		case n, ok := <-kubeCh:
			if !ok {
				return
			}
			data, mErr := json.Marshal(n.Data)
			if mErr != nil {
				a.log.ErrorContext(ctx, "encode kube event", "err", mErr)
				continue
			}
			_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", n.Type, data)
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
	c, err := r.Cookie(sessionCookieName(r))
	if err != nil {
		return time.Time{}, err
	}
	if c.Value == "" {
		return time.Time{}, store.ErrNotFound
	}
	return a.store.Admin().CheckSession(r.Context(), c.Value, a.now())
}

// sessionCookieName is the session cookie for the request's scheme.
func sessionCookieName(r *http.Request) string {
	if r.TLS != nil {
		return SecureSessionCookie
	}
	return SessionCookie
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

// writeNotOwner answers a request on a master that does not own the token,
// approval or link it uses (store.ErrNotOwner), naming the master that does.
func (a *api) writeNotOwner(ctx context.Context, w http.ResponseWriter, err error) {
	owner := store.OwnerOf(err)
	msg := err.Error()
	if a.masters != nil {
		if u := a.masters.AgentURLOf(ctx, owner); u != "" {
			msg += "; open it at " + u
		}
	}
	writeError(w, http.StatusConflict, "not_owner", msg)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeRetry is writeError with a Retry-After of after, rounded up to a second.
func writeRetry(w http.ResponseWriter, status int, after time.Duration, code, msg string) {
	w.Header().Set("Retry-After", strconv.Itoa(int((after+time.Second-1)/time.Second)))
	writeError(w, status, code, msg)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, ErrorJSON{Error: msg, Code: code})
}

// writeUnavailable answers a write that a clustered hub could not get to the
// leader, or whose leader changed under it (store.ErrUnavailable). Retrying
// is safe.
func writeUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "cluster_unavailable",
		"no cluster leader is reachable right now; try again shortly")
}

// automationsLock is l, or a private lock when the hub gave none.
func automationsLock(l sync.Locker) sync.Locker {
	if l == nil {
		return new(sync.Mutex)
	}
	return l
}
