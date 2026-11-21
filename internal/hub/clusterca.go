// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// ClusterCA shows and moves on the hub CA rotation of an AP cluster
// (docs/cluster.md, "Rotating the hub CA"): cluster.APNode, through an
// adapter.
type ClusterCA interface {
	// CAStatus is the latest rotation and every member's side of it.
	CAStatus(ctx context.Context) (ClusterCAJSON, error)
	// ChangeCA runs the step op (rotate, finish or abort) on this master as
	// the actor, through policy, with precheck as the request's Precheck. A
	// step refused before it runs (another master owns the rotation, say)
	// is an audited denial whose error matches the refusal.
	ChangeCA(ctx context.Context, op, actorKind, actorID string, precheck func(context.Context) error) error
	// CAErrorKind names a refusal of a step ("rotation_owner",
	// "old_ca_holders", ...), or "" for any other error.
	CAErrorKind(err error) string
}

// ClusterCAJSON is GET /api/v1/cluster/ca: the latest hub CA rotation and
// every member's side of it.
type ClusterCAJSON struct {
	// NodeID is this hub's.
	NodeID string `json:"node_id"`
	// Rotation is the latest rotation; none if there has been none.
	Rotation *CARotationJSON `json:"rotation,omitempty"`
	Hubs     []MemberCAJSON  `json:"hubs"`
	// OldDevices still hold only an old-CA certificate during a rotation:
	// a finish refuses while there are any.
	OldDevices []string `json:"old_devices,omitempty"`
}

// CARotationJSON is a hub CA rotation.
type CARotationJSON struct {
	NewCAFP string `json:"new_ca_fp"`
	OldCAFP string `json:"old_ca_fp"`
	// Stage is started, cutover, finished or aborted.
	Stage     string    `json:"stage"`
	Active    bool      `json:"active"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Owner is the master that drives it; OwnerAlive whether it is a live
	// master, and OwnerURL where its UI and agents are served, if known.
	Owner      string `json:"owner"`
	OwnerAlive bool   `json:"owner_alive"`
	OwnerURL   string `json:"owner_url,omitempty"`
}

// MemberCAJSON is one member's side of a hub CA rotation, as it says on the
// gossip. The fingerprints are the gossip's short form.
type MemberCAJSON struct {
	ID     string `json:"id"`
	Master bool   `json:"master"`
	// Serving is the CA it presents; Next the new CA it trusts.
	Serving     string `json:"serving,omitempty"`
	Next        string `json:"next,omitempty"`
	HasNextKey  bool   `json:"has_next_key,omitempty"`
	HasNextCert bool   `json:"has_next_cert,omitempty"`
	CutOver     bool   `json:"cut_over,omitempty"`
	// Error is why its side is unknown: its state (dead, left, ...) or
	// that it says nothing yet.
	Error string `json:"error,omitempty"`
}

// Hub CA rotation steps of POST /api/v1/cluster/ca/{op}.
var caOps = []string{"rotate", "finish", "abort"}

func (a *api) clusterCARoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/cluster/ca", a.auth(a.clusterCAStatus))
	mux.Handle("POST /api/v1/cluster/ca/{op}", a.auth(a.clusterCAChange))
	mux.Handle("POST /api/v1/cluster/tokens", a.auth(a.createClusterToken))
}

// clusterCAStatus answers the hub CA rotation's status; 404 outside an AP
// cluster.
func (a *api) clusterCAStatus(w http.ResponseWriter, r *http.Request) {
	if a.clusterCA == nil {
		writeError(w, http.StatusNotFound, "not_ap_cluster", "this hub is not a member of an AP cluster")
		return
	}
	st, err := a.clusterCA.CAStatus(r.Context())
	if err != nil {
		a.writeCAError(w, r, "read the hub CA rotation", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// clusterCAChange starts, finishes or aborts a hub CA rotation on this
// master, as `hearth cluster ca rotate|finish|abort` does on its host:
// dangerous, decided by policy as web and audited, refusals included, and
// only with the admin password entered again. It answers the status after.
func (a *api) clusterCAChange(w http.ResponseWriter, r *http.Request) {
	if a.clusterCA == nil {
		writeError(w, http.StatusNotFound, "not_ap_cluster", "this hub is not a member of an AP cluster")
		return
	}
	op := r.PathValue("op")
	if !slices.Contains(caOps, op) {
		writeError(w, http.StatusNotFound, "not_found", "the steps are rotate, finish and abort")
		return
	}
	if err := a.clusterCA.ChangeCA(r.Context(), op, policy.ActorWeb, remoteHost(r), a.recentAuth(r)); err != nil {
		a.writeCAError(w, r, "hub CA "+op, err)
		return
	}
	a.clusterCAStatus(w, r)
}

// writeCAError answers a hub CA rotation step that failed or was refused.
func (a *api) writeCAError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, errReauthRequired):
		writeError(w, http.StatusForbidden, "reauth_required", "enter the admin password again to do this")
	case errors.Is(err, policy.ErrDenied) && strings.Contains(err.Error(), policy.ErrIsolated):
		writeError(w, http.StatusForbidden, "isolated", policy.ErrIsolated)
	case a.clusterCA.CAErrorKind(err) != "":
		writeError(w, http.StatusConflict, a.clusterCA.CAErrorKind(err), err.Error())
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	case r.Context().Err() != nil:
		// The client went away.
	default:
		// A member down, or one that did not catch up in time: its words.
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusBadGateway, "rotation_failed", err.Error())
	}
}

// ClusterTokenJSON is a created cluster join token. Token is the secret: it
// is answered once, and never logged, audited or stored (only its hash).
type ClusterTokenJSON struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	// HubURL is this master's: the token belongs to it, so the new hub
	// joins through it.
	HubURL string `json:"hub_url"`
	// JoinCommand runs the new hub, with an empty data dir.
	JoinCommand string `json:"join_command"`
}

// createClusterToken creates a single-use cluster join token, as `hearth
// cluster token create` does: dangerous, since whoever redeems it with the
// master role allowed receives the CA key, and only with the admin password
// entered again. AllowRoles only shape the join command's --allow-roles:
// the joining host decides its roles, and the token does not limit them.
func (a *api) createClusterToken(w http.ResponseWriter, r *http.Request) {
	if a.clusterCA == nil {
		writeError(w, http.StatusNotFound, "not_ap_cluster", "this hub is not a member of an AP cluster")
		return
	}
	var body struct {
		TTL        string   `json:"ttl"`
		AllowRoles []string `json:"allow_roles"`
	}
	if !decodeJSON(w, r, maxTokenBody, &body, `{"ttl"?: "15m", "allow_roles"?: ["storage", "master"]}`) {
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
	roles, ok := joinRoles(body.AllowRoles)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "allow_roles are storage and master")
		return
	}
	_, agentHost, ok := a.commandHosts(r.Host, r.TLS != nil)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "request Host header is not a valid host name")
		return
	}
	tok, err := pki.NewToken(a.ca.Cert())
	if err != nil {
		a.log.ErrorContext(r.Context(), "create cluster join token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot create the join token")
		return
	}
	expires := a.now().Add(ttl).UTC().Truncate(time.Millisecond)
	err = a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.ClusterTokenCreate,
		Detail:   map[string]any{"ttl": ttl.String(), "allow_roles": cmp.Or(roles, "storage,master")},
		Precheck: a.recentAuth(r),
	}, func(ctx context.Context) error {
		return a.store.JoinTokens().Create(ctx, tok.Secret, expires)
	})
	switch {
	case err == nil:
	case !errors.Is(err, errReauthRequired) && errors.Is(err, policy.ErrDenied) &&
		strings.Contains(err.Error(), policy.ErrIsolated):
		writeError(w, http.StatusForbidden, "isolated", policy.ErrIsolated)
		return
	default:
		a.writeActionError(w, r, "create the cluster join token", err)
		return
	}
	a.log.InfoContext(r.Context(), "cluster join token created", "remote", remoteHost(r), "ttl", ttl.String())
	hubURL := "https://" + net.JoinHostPort(agentHost, a.agentPort)
	enc := tok.EncodeJoin()
	cmd := "HEARTH_JOIN_TOKEN=" + enc + " hearth hub --join " + hubURL
	if roles != "" {
		cmd += " --allow-roles " + roles
	}
	// The host is checked (commandHosts) and the token is base64url and
	// dots: the command is safe to paste into a shell. The token goes in
	// the environment, not argv, which any local user can read.
	writeJSON(w, http.StatusCreated, ClusterTokenJSON{Token: enc, ExpiresAt: expires, HubURL: hubURL, JoinCommand: cmd})
}

// joinRoles is the --allow-roles of a join command for roles: "" for the
// default (storage and master, or none given), and ok false for an unknown
// role.
func joinRoles(roles []string) (string, bool) {
	storage, master := false, false
	for _, r := range roles {
		switch r {
		case "storage":
			storage = true
		case "master":
			master = true
		default:
			return "", false
		}
	}
	switch {
	case storage == master:
		return "", true
	case storage:
		return "storage", true
	default:
		return "master", true
	}
}
