// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
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
		out = append(out, approvalJSON(ap))
	}
	writeJSON(w, http.StatusOK, out)
}

// errNoPassword is the re-authentication error of an approve request that
// carries no password.
var errNoPassword = errors.New("no password given")

// approvePassword reads the approver's password from an approve request's
// {"password": "..."} body. A request without one, or without a JSON body,
// gets "": refused and audited like a wrong password.
func approvePassword(w http.ResponseWriter, r *http.Request) (string, bool) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return "", true
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {\"password\": \"...\"}")
		return "", false
	}
	return body.Password, true
}

// decideApproval approves or denies a held action, as the web session.
// Approving re-authenticates the approver: the request carries the admin
// password, checked as login checks it and under login's rate limit, so a
// session alone, such as a stolen cookie, cannot approve. Denying needs no
// password.
func (a *api) decideApproval(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var reauth func(context.Context) error
		if approve {
			password, ok := approvePassword(w, r)
			if !ok {
				return
			}
			// Only a guess costs an argon2 verification, and counts as one.
			if password != "" {
				if ok, wait := a.logins.allow(remoteHost(r)); !ok {
					writeRetry(w, http.StatusTooManyRequests, wait, "rate_limited", "too many password attempts; try again later")
					return
				}
			}
			reauth = func(ctx context.Context) error {
				if password == "" {
					return errNoPassword
				}
				return a.checkAdminPassword(ctx, password)
			}
		}
		id := r.PathValue("id")
		err := a.policy.Decide(ctx, policy.ActorWeb, remoteHost(r), id, approve, reauth)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such approval")
		case errors.Is(err, store.ErrApprovalClosed):
			writeError(w, http.StatusConflict, "closed", "the approval is no longer pending")
		case errors.Is(err, errWrongPassword), errors.Is(err, errNoPassword):
			a.log.WarnContext(ctx, "approval refused: wrong or missing password", "approval", id, "remote", remoteHost(r))
			writeError(w, http.StatusForbidden, "reauth_failed", "approving needs your password, and it was missing or wrong")
		case errors.Is(err, errVerifyBusy):
			writeRetry(w, http.StatusServiceUnavailable, a.verifyWait, "busy", "the hub is busy checking other passwords; try again shortly")
		case errors.Is(err, store.ErrUnavailable):
			writeUnavailable(w)
		case ctx.Err() != nil:
			return // the client went away
		case errors.Is(err, policy.ErrReauth):
			a.log.ErrorContext(ctx, "approval refused: cannot check the password", "approval", id, "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot check the password")
		case errors.Is(err, policy.ErrDenied):
			writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
		default:
			a.log.ErrorContext(ctx, "decide approval", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot decide the approval")
		}
	}
}
