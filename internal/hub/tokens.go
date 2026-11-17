// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

const (
	// DefaultAgentPort is the hub's default TLS port for agents.
	DefaultAgentPort = "7443"
	defaultTokenTTL  = 15 * time.Minute
	maxTokenTTL      = 24 * time.Hour
	maxTokenBody     = 4 << 10
	maxTokenLabels   = 32
	maxLabelLen      = 128
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
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTokenBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"ttl"?: "15m", "labels"?: {"k": "v"}}`)
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
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb,
		ActorID:   remoteHost(r),
		Action:    policy.TokenCreate,
		Detail:    map[string]any{"ttl": ttl.String(), "labels": body.Labels},
	}, func(ctx context.Context) error {
		return a.store.Tokens().Create(ctx, tok.Secret, body.Labels, expires)
	})
	switch {
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "token creation denied by policy")
		return
	case err != nil:
		a.log.ErrorContext(ctx, "create token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot create token")
		return
	}

	a.log.InfoContext(ctx, "enrollment token created", "remote", remoteHost(r), "ttl", ttl.String())
	agentURL := "https://" + net.JoinHostPort(agentHost, a.agentPort)
	enc := tok.Encode()
	writeJSON(w, http.StatusCreated, TokenJSON{
		Token:     enc,
		ExpiresAt: expires,
		// Every part is checked above (host characters) or base64url, so the
		// command is safe to paste into a shell. The token goes in the
		// environment of sh and hearth, not their argv: any local user can
		// read argv with ps, but not another user's environment. No sudo in
		// the join command: sudo drops HEARTH_TOKEN, and putting it after
		// sudo would put it in sudo's argv. Run as root, join uses the
		// installed service's data dir.
		InstallCommand: "curl -fsSL http://" + httpHost + "/install.sh | HEARTH_TOKEN=" + enc + " sh -s -- --hub " + agentURL,
		JoinCommand:    "HEARTH_TOKEN=" + enc + " hearth agent join " + agentURL,
	})
}

// commandHosts derives the hosts for the install and join commands from the
// Host the browser used. Over plain HTTP the install script comes from that
// same address. Over HTTPS it comes from the HTTP listener on the same host
// instead: curl on a fresh device does not trust the hub CA yet.
// Agents verify the hub certificate by name, so the agent URL uses that host
// only if the certificate covers it, and the first certificate name otherwise.
func (a *api) commandHosts(reqHost string, overTLS bool) (httpHost, agentHost string, ok bool) {
	host, port := reqHost, ""
	if h, p, err := net.SplitHostPort(reqHost); err == nil {
		host, port = h, p
	}
	if !validHost(host) || !validPort(port) {
		return "", "", false
	}
	httpHost = host
	if strings.Contains(host, ":") {
		httpHost = "[" + host + "]"
	}
	if overTLS {
		port = a.httpPort
	}
	if port != "" {
		httpHost = net.JoinHostPort(host, port)
	}
	agentHost = host
	if len(a.agentHosts) > 0 && !slices.ContainsFunc(a.agentHosts, func(h string) bool { return strings.EqualFold(h, host) }) {
		agentHost = a.agentHosts[0]
	}
	return httpHost, agentHost, true
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
