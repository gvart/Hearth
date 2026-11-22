// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// ClusterAdmin promotes, demotes and removes the members of an AP cluster
// (docs/design/ap-cluster.md §2): cluster.APNode, through an adapter.
type ClusterAdmin interface {
	// Status is this hub's view of the cluster and its members, as JSON.
	Status(ctx context.Context) any
	Promote(ctx context.Context, member, role string) (any, error)
	Demote(ctx context.Context, member, role string) (any, error)
	Remove(ctx context.Context, member string) (any, error)
	// ErrorKind names a refusal of these ("last_master", "not_allowed",
	// "unknown_member", ...), or "" for any other error.
	ErrorKind(err error) string
}

// Cluster role change operations.
const (
	ClusterOpPromote = "promote"
	ClusterOpDemote  = "demote"
	ClusterOpRemove  = "remove"
)

// ClusterChange is a promotion, a demotion or a removal of a member.
type ClusterChange struct {
	Op     string `json:"op"`
	Member string `json:"member"`
	// Role is storage or master; none for a removal.
	Role string `json:"role,omitempty"`
}

// errBadClusterChange refuses a change that names no valid operation,
// member or role.
var errBadClusterChange = errors.New("a change is promote or demote with a role (storage or master), or remove, of a member")

// memberIDChars are the characters of a node ID.
const memberIDChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"

// Check refuses a malformed change before it reaches policy, so the audit
// log only names well-formed ones.
func (c ClusterChange) Check() error {
	if c.Member == "" || len(c.Member) > 128 || strings.ContainsFunc(c.Member, func(r rune) bool {
		return !strings.ContainsRune(memberIDChars, r)
	}) {
		return errBadClusterChange
	}
	switch c.Op {
	case ClusterOpPromote, ClusterOpDemote:
		if c.Role != "storage" && c.Role != "master" {
			return errBadClusterChange
		}
	case ClusterOpRemove:
		if c.Role != "" {
			return errBadClusterChange
		}
	default:
		return errBadClusterChange
	}
	return nil
}

// DoClusterChange runs c on admin as actor through pol: decided as
// cluster.promote, cluster.demote or cluster.remove (dangerous), audited
// with its outcome. A dry run decides and audits, and changes nothing.
func DoClusterChange(ctx context.Context, pol *policy.Engine, admin ClusterAdmin, actorKind, actorID string,
	c ClusterChange, dryRun bool, onHold func(id string, expires time.Time),
) (any, error) {
	if err := c.Check(); err != nil {
		return nil, err
	}
	req := ClusterChangeRequest(c, actorKind, actorID)
	req.DryRun, req.OnHold = dryRun, onHold
	var out any
	err := pol.Do(ctx, req, func(ctx context.Context) error {
		var err error
		switch c.Op {
		case ClusterOpPromote:
			out, err = admin.Promote(ctx, c.Member, c.Role)
		case ClusterOpDemote:
			out, err = admin.Demote(ctx, c.Member, c.Role)
		default:
			out, err = admin.Remove(ctx, c.Member)
		}
		return err
	})
	return out, err
}

// ClusterChangeRequest is the policy request of c by an actor.
func ClusterChangeRequest(c ClusterChange, actorKind, actorID string) policy.Request {
	action := map[string]policy.Action{
		ClusterOpPromote: policy.ClusterPromote, ClusterOpDemote: policy.ClusterDemote, ClusterOpRemove: policy.ClusterRemove,
	}[c.Op]
	req := policy.Request{ActorKind: actorKind, ActorID: actorID, Action: action, Target: c.Member}
	if c.Role != "" {
		req.Detail = map[string]any{"role": c.Role}
	}
	return req
}

func (a *api) clusterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/cluster/members", a.auth(a.clusterMembers))
	mux.Handle("POST /api/v1/cluster/members/{id}/promote", a.auth(a.clusterChange(ClusterOpPromote)))
	mux.Handle("POST /api/v1/cluster/members/{id}/demote", a.auth(a.clusterChange(ClusterOpDemote)))
	mux.Handle("DELETE /api/v1/cluster/members/{id}", a.auth(a.clusterChange(ClusterOpRemove)))
}

// clusterMembers lists the members of an AP cluster; 404 on any other hub.
func (a *api) clusterMembers(w http.ResponseWriter, r *http.Request) {
	if a.clusterAdmin == nil {
		writeError(w, http.StatusNotFound, "not_ap_cluster", "this hub is not a member of an AP cluster")
		return
	}
	writeJSON(w, http.StatusOK, a.clusterAdmin.Status(r.Context()))
}

// clusterChange promotes, demotes or removes a member, as the web UI asks.
func (a *api) clusterChange(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.clusterAdmin == nil {
			writeError(w, http.StatusNotFound, "not_ap_cluster", "this hub is not a member of an AP cluster")
			return
		}
		c := ClusterChange{Op: op, Member: r.PathValue("id")}
		if op != ClusterOpRemove {
			var body struct {
				Role string `json:"role"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", "the body is {\"role\": \"storage\" or \"master\"}")
				return
			}
			c.Role = body.Role
		}
		out, err := DoClusterChange(r.Context(), a.policy, a.clusterAdmin, policy.ActorWeb, remoteHost(r), c, false, nil)
		if err != nil {
			a.writeClusterError(w, r, op, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// clusterStatus is the HTTP status of each refusal of a role change.
var clusterStatus = map[string]int{
	"unknown_member": http.StatusNotFound,
	"bad_role":       http.StatusBadRequest,
}

// writeClusterError answers a failed role change.
func (a *api) writeClusterError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, errBadClusterChange):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, policy.ErrDenied) && strings.Contains(err.Error(), policy.ErrIsolated):
		writeError(w, http.StatusForbidden, "isolated", policy.ErrIsolated)
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case a.clusterAdmin.ErrorKind(err) != "":
		kind := a.clusterAdmin.ErrorKind(err)
		status, ok := clusterStatus[kind]
		if !ok {
			status = http.StatusConflict
		}
		writeError(w, status, kind, err.Error())
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	case r.Context().Err() != nil:
	default:
		a.log.ErrorContext(r.Context(), "cluster "+op, "err", err)
		writeError(w, http.StatusBadGateway, "member_failed", err.Error())
	}
}
