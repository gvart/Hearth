// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// DefaultAgentPort is the hub's default TLS port for agents.
	DefaultAgentPort = "7443"
	defaultTokenTTL  = 15 * time.Minute
	maxTokenTTL      = 24 * time.Hour
	maxTokenBody     = 4 << 10
	maxTokenLabels   = 32
	maxLabelLen      = 128
	maxDeviceNameLen = 63
)

// DefaultHTTPPort is the hub's default plain-HTTP port for the UI and the
// install script.
const DefaultHTTPPort = "7080"

// TokenJSON is the body of a successful POST /tokens. Token is the secret;
// it is returned once and never logged.
type TokenJSON struct {
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
	InstallCommand string    `json:"install_command"`
	JoinCommand    string    `json:"join_command"`
}

// DryRunJSON answers a dry run: the decision policy made and audited, allow
// or confirm (a denial is an error). Nothing was done.
type DryRunJSON struct {
	DryRun   bool   `json:"dry_run"`
	Decision string `json:"decision"`
}

// createToken mints a single-use enrollment token for the web UI's "Add
// device" dialog, with the commands that use it.
func (a *api) createToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var body struct {
		TTL    string            `json:"ttl"`
		Labels map[string]string `json:"labels"`
		// Name names the device that enrolls with the token; empty leaves
		// it its hostname.
		Name string `json:"name"`
		// Hub lets a capable device that enrolls with the token become a
		// hub (#328): it hands the CA key to a master, so it needs the
		// password again and its own cluster.token.create decision.
		Hub bool `json:"hub"`
		// DryRun decides and audits the request without creating a token.
		DryRun bool `json:"dry_run"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTokenBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"ttl"?: "15m", "labels"?: {"k": "v"}, "name"?: "garage-pi", "hub"?: false, "dry_run"?: false}`)
		return
	}
	ttl := defaultTokenTTL
	if body.TTL != "" {
		d, err := time.ParseDuration(body.TTL)
		if err != nil || d <= 0 || d > maxTokenTTL {
			writeError(w, http.StatusBadRequest, "bad_request", "ttl must be a positive duration of at most 24h, e.g. \"15m\"")
			return
		}
		ttl = d
	}
	if msg := checkLabels(body.Labels); msg != "" {
		writeError(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	name, err := DeviceName(body.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if body.Hub && a.clusterCA == nil {
		writeError(w, http.StatusNotFound, "not_ap_cluster", "this hub is not a member of an AP cluster")
		return
	}
	httpHost, agentHost, ok := a.commandHosts(r.Host, r.TLS != nil)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "request Host header is not a valid host name")
		return
	}

	tok, err := pki.NewToken(a.ca.Cert())
	if err != nil {
		a.log.ErrorContext(ctx, "create token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot create token")
		return
	}
	expires := a.now().Add(ttl).UTC().Truncate(time.Millisecond)
	req := policy.Request{
		ActorKind: policy.ActorWeb,
		ActorID:   remoteHost(r),
		Action:    policy.TokenCreate,
		Detail:    TokenDetail(ttl, body.Labels, name),
		DryRun:    body.DryRun,
	}
	hubRoles := ""
	if body.Hub {
		hubRoles = allJoinRoles
		req.Detail["hub"] = true
	}
	create := func(ctx context.Context) error {
		return a.store.Tokens().CreateHub(ctx, tok.Secret, name, hubRoles, body.Labels, expires)
	}
	var hubReq policy.Request
	if body.Hub {
		// The token hands the CA key to whoever redeems it on a capable
		// device: decided as Add hub's join token is, nested in token.create.
		hubReq = policy.Request{
			ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.ClusterTokenCreate,
			Detail:   ClusterTokenDetail(ttl, tok.Secret),
			Precheck: a.recentAuth(r), DryRun: body.DryRun,
		}
		plain := create
		create = func(ctx context.Context) error { return a.policy.Do(ctx, hubReq, plain) }
	}
	err = a.policy.Do(ctx, req, create)
	if err == nil && body.DryRun && body.Hub {
		err = a.policy.Do(ctx, hubReq, func(context.Context) error { return nil })
	}
	switch {
	case errors.Is(err, errReauthRequired):
		writeError(w, http.StatusForbidden, "reauth_required", "enter the admin password again to do this")
		return
	case errors.Is(err, policy.ErrDenied) && strings.Contains(err.Error(), policy.ErrIsolated):
		writeError(w, http.StatusForbidden, "isolated", policy.ErrIsolated)
		return
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "token creation denied by policy")
		return
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
		return
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old", "the hub cluster's database predates this kind of token (named or hub-eligible): upgrade every hub of the cluster first")
		return
	case err != nil:
		a.log.ErrorContext(ctx, "create token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot create token")
		return
	case body.DryRun:
		decision, _ := a.policy.Check(req)
		if body.Hub && decision == policy.Allow {
			decision, _ = a.policy.Check(hubReq)
		}
		writeJSON(w, http.StatusOK, DryRunJSON{DryRun: true, Decision: decision})
		return
	}

	a.log.InfoContext(ctx, "enrollment token created", "remote", remoteHost(r), "ttl", ttl.String())
	agentURL := "https://" + net.JoinHostPort(agentHost, a.agentPort)
	// The token says where the hub is, so neither command repeats it. In a
	// cluster only this master can use it.
	enc := tok.EncodeHub(agentURL)
	writeJSON(w, http.StatusCreated, TokenJSON{
		Token:     enc,
		ExpiresAt: expires,
		// Every part is checked above (host characters, release tag) or
		// base64url, so the command is safe to paste into a shell. The token
		// goes in the environment of sh and hearth, not their argv: any local
		// user can read argv with ps, but not another user's environment. No
		// sudo in the join command: sudo drops HEARTH_TOKEN, and putting it
		// after sudo would put it in sudo's argv. Run as root, join uses the
		// installed service's data dir.
		InstallCommand: a.installCommand(httpHost, enc),
		JoinCommand:    "HEARTH_TOKEN=" + enc + " hearth agent join",
	})
}

// installScriptURL is where a release hub's install command fetches
// install.sh: the script of its own release tag, over HTTPS from GitHub.
const installScriptURL = "https://raw.githubusercontent.com/gvart/Hearth/"

// installCommand is the one-liner that installs and enrolls a device. A
// release hub pins the agent to its own release, so agent and hub match and
// the installer need not look up the latest release (which GitHub does not
// report while every release is a pre-release); the piped script cannot know
// its tag, hence --version. A dev hub serves its own install.sh, from the
// HTTP listener at httpHost, and the installer picks the newest release.
func (a *api) installCommand(httpHost, token string) string {
	if a.installVersion == "" {
		return "curl -fsSL http://" + httpHost + "/install.sh | HEARTH_TOKEN=" + token + " sh"
	}
	return "curl -fsSL " + installScriptURL + a.installVersion + "/deploy/install.sh | HEARTH_TOKEN=" + token +
		" sh -s -- --version " + a.installVersion
}

// releaseTag matches the release tags goreleaser builds from: vX.Y.Z with an
// optional dot-separated pre-release (v0.0.1-rc.5). It refuses a hyphen inside
// the pre-release, which leaves out Go pseudo-versions
// (v0.0.0-20250101000000-abcdef123456), and anything a shell would interpret.
var releaseTag = sync.OnceValue(func() *regexp.Regexp {
	return regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
})

// releaseVersion returns version if it names a release the installer can
// download, and "" for dev, snapshot (vX.Y.Z-snapshot, see .goreleaser.yaml)
// and pseudo-version builds.
func releaseVersion(version string) string {
	if !releaseTag().MatchString(version) || strings.HasSuffix(version, "-snapshot") {
		return ""
	}
	return version
}

// commandHosts derives the hosts for the install and join commands from the
// Host the browser used. Agents verify the hub certificate by name, so the
// agent host is the browser's host only if the certificate covers it and it
// is not a loopback address, which means nothing on another device, nor a
// bare hostname (BareHostname) when the first certificate name that is not
// loopback is an IP, nor discovery.LANName, which only the master announcing
// it answers at; else it is that first name. With no such name it
// stays the browser's host: no choice works then. The install script
// comes from the HTTP listener at the browser's address when the agent host
// is the browser's host and the page came over plain HTTP; otherwise from the
// HTTP listener at the agent host (curl on a fresh device does not trust the
// hub CA yet, so never from the HTTPS port).
func (a *api) commandHosts(reqHost string, overTLS bool) (httpHost, agentHost string, ok bool) {
	host, port := reqHost, ""
	if h, p, err := net.SplitHostPort(reqHost); err == nil {
		host, port = h, p
	}
	if !validHost(host) || !validPort(port) {
		return "", "", false
	}
	agentHost = host
	if i := slices.IndexFunc(a.agentHosts, func(h string) bool { return !isLoopback(h) }); i >= 0 {
		first := a.agentHosts[i]
		inCert := slices.ContainsFunc(a.agentHosts, func(h string) bool { return strings.EqualFold(h, host) })
		if isLoopback(host) || !inCert || (BareHostname(host) && net.ParseIP(first) != nil) ||
			strings.EqualFold(strings.TrimSuffix(host, "."), discovery.LANName) {
			agentHost = first
		}
	}
	if overTLS || agentHost != host {
		port = a.httpPort
	}
	httpHost = agentHost
	if port != "" {
		httpHost = net.JoinHostPort(agentHost, port)
	} else if strings.Contains(agentHost, ":") {
		httpHost = "[" + agentHost + "]"
	}
	return httpHost, agentHost, true
}

// BareHostname reports whether host is a name other devices are unlikely to
// resolve: a single label, such as an OS hostname, or an mDNS .local name,
// which devices without an mDNS resolver cannot look up.
func BareHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" || net.ParseIP(h) != nil {
		return false
	}
	return !strings.Contains(h, ".") || strings.HasSuffix(h, ".local")
}

// isLoopback reports whether host names this machine only: localhost (and
// its subdomains) or a loopback IP.
func isLoopback(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validPort(p string) bool {
	if p == "" {
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == p
}

// validHost admits DNS names and IP literals, and nothing a shell would
// interpret.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, c := range h {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// DeviceName checks the device name an enrollment token gives and returns it
// trimmed; "" names none. A name is 1 to 63 letters, digits, '.', '-' or '_',
// starting with a letter or digit: hostname-like, as the agent hostname it
// replaces usually is.
func DeviceName(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	name = strings.TrimSpace(name)
	if len(name) > maxDeviceNameLen || !deviceNameRE().MatchString(name) {
		return "", errors.New("name must be 1 to 63 letters, digits, ., - or _, starting with a letter or digit")
	}
	return name, nil
}

var deviceNameRE = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`) })

// TokenDetail is the audited detail of an enrollment token creation.
func TokenDetail(ttl time.Duration, labels map[string]string, name string) map[string]any {
	d := map[string]any{"ttl": ttl.String(), "labels": labels}
	if name != "" {
		d["name"] = name
	}
	return d
}

// ClusterTokenDetail is the audited detail of the cluster.token.create decision
// for a hub-eligible enrollment token: the roles it may lead to, its TTL and
// its handle, the actor ID of the device.enroll entry that redeems it.
func ClusterTokenDetail(ttl time.Duration, secret string) map[string]any {
	return map[string]any{"via": "enrollment_token", "roles": allJoinRoles, "ttl": ttl.String(), "token": tokenActorID(secret)}
}

func checkLabels(labels map[string]string) string {
	if len(labels) > maxTokenLabels {
		return "too many labels"
	}
	for k, v := range labels {
		if k == "" || len(k) > maxLabelLen || len(v) > maxLabelLen {
			return "label keys must be 1-128 bytes and values at most 128 bytes"
		}
	}
	return ""
}
