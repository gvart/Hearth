// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// approvalsListed is how many approvals GET /api/v1/approvals returns.
const approvalsListed = 100

// ApprovalJSON is an action held for approval, as the API serves it.
type ApprovalJSON struct {
	ID        string          `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	ActorKind string          `json:"actor_kind"`
	ActorID   string          `json:"actor_id"`
	Action    string          `json:"action"`
	Class     string          `json:"class"`
	Target    string          `json:"target"`
	Detail    json.RawMessage `json:"detail"`
	Status    string          `json:"status"`
	DecidedBy string          `json:"decided_by,omitempty"`
	DecidedAt *time.Time      `json:"decided_at,omitempty"`
}

// listApprovals serves the newest approvals: the pending ones, or all of
// them with ?status=all.
func (a *api) listApprovals(w http.ResponseWriter, r *http.Request) {
	status := store.ApprovalPending
	switch q := r.URL.Query().Get("status"); q {
	case "", store.ApprovalPending:
	case "all":
		status = ""
	case store.ApprovalApproved, store.ApprovalDenied, store.ApprovalExpired:
		status = q
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "status must be pending, approved, denied, expired or all")
		return
	}
	aps, err := a.store.Approvals().List(r.Context(), status, approvalsListed)
	if err != nil {
		a.log.ErrorContext(r.Context(), "list approvals", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot list approvals")
		return
	}
	out := make([]ApprovalJSON, 0, len(aps))
	for _, ap := range aps {
		j := ApprovalJSON{
			ID: ap.ID, CreatedAt: ap.CreatedAt, ExpiresAt: ap.ExpiresAt, ActorKind: ap.ActorKind,
			ActorID: ap.ActorID, Action: ap.Action, Class: ap.Class, Target: ap.Target, Detail: ap.Detail,
			Status: ap.Status, DecidedBy: ap.DecidedBy,
		}
		if !ap.DecidedAt.IsZero() {
			j.DecidedAt = &ap.DecidedAt
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

// decideApproval approves or denies a held action, as the web session.
func (a *api) decideApproval(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := a.policy.Decide(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), approve)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such approval")
		case errors.Is(err, store.ErrApprovalClosed):
			writeError(w, http.StatusConflict, "closed", "the approval is no longer pending")
		case errors.Is(err, policy.ErrDenied):
			writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
		case errors.Is(err, store.ErrUnavailable):
			writeUnavailable(w)
		default:
			a.log.ErrorContext(r.Context(), "decide approval", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot decide the approval")
		}
	}
}
