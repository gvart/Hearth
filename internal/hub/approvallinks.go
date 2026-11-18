// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// Approval links.
//
// When the policy file names an approval_notify channel, every held action
// is sent there with a link to the web UI's #/approve/<secret> page. The
// secret is the link's only credential, for that one approval: 256 random
// bits, stored hashed, spent by its first approve or deny, and expiring
// with the approval. It travels in the URL fragment, which browsers never
// send to a server, and then in a POST body: never in a path, a query or a
// log. Opening the page only shows the action; deciding takes a tap.

// approvalLinkPath is the web UI route of an approval link; the secret
// follows it.
const approvalLinkPath = "/#/approve/"

// maxLinkBody bounds the body of an approval link request.
const maxLinkBody = 4 << 10

// ApprovalNotifierConfig is what NewApprovalNotifier needs.
type ApprovalNotifierConfig struct {
	Links    store.ApprovalLinks
	Notifier *notify.Notifier
	// Channel is the notification channel to send to.
	Channel string
	// BaseURL is the hub's web UI as the phone reaches it, without a
	// trailing slash.
	BaseURL string
	Log     *slog.Logger
}

// NewApprovalNotifier returns a policy.Engine OnHeld hook that sends every
// held action to cfg.Channel with an approval link. A link that cannot be
// stored (a cluster before schema 10) leaves the message without one; a
// failed send is logged, and the approval waits as it would anyway.
func NewApprovalNotifier(cfg ApprovalNotifierConfig) func(ctx context.Context, ap store.Approval) {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return func(ctx context.Context, ap store.Approval) {
		msg := approvalMessage(ap)
		secret, err := newSessionSecret()
		if err == nil {
			err = cfg.Links.Create(ctx, secret, ap.ID, ap.ExpiresAt)
		}
		if err != nil {
			cfg.Log.WarnContext(ctx, "approval link not created; notifying without it", "approval", ap.ID, "err", err)
			msg.Body += "\nApprove or deny it in Hearth."
		} else {
			msg.Link, msg.LinkLabel = base+approvalLinkPath+secret, "Review"
		}
		if err := cfg.Notifier.SendMessage(ctx, cfg.Channel, msg); err != nil {
			// The error names the channel and the provider's reason only.
			cfg.Log.WarnContext(ctx, "approval notification not sent", "approval", ap.ID, "err", err)
		}
	}
}

// approvalMessage describes a held action. The detail is the request's
// audit detail, which never holds secrets.
func approvalMessage(ap store.Approval) notify.Message {
	body := fmt.Sprintf("%s/%s wants to run %s", ap.ActorKind, ap.ActorID, ap.Action)
	if ap.Target != "" {
		body += " on " + ap.Target
	}
	body += fmt.Sprintf(" (%s).", ap.Class)
	if d := string(ap.Detail); d != "" && d != "{}" {
		if len(d) > 300 {
			d = d[:300] + "…"
		}
		body += "\n" + d
	}
	body += "\nExpires " + ap.ExpiresAt.UTC().Format("15:04:05 UTC") + "; unanswered, it is denied."
	return notify.Message{Title: "Approval needed: " + ap.Action, Body: body}
}

// approvalLinkRoutes serves the approval link page's API. It has no
// session check: the link's secret, in the body, is the credential.
func (a *api) approvalLinkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/approval-link", a.peekApprovalLink)
	mux.HandleFunc("POST /api/v1/approval-link/approve", a.decideApprovalLink(true))
	mux.HandleFunc("POST /api/v1/approval-link/deny", a.decideApprovalLink(false))
}

// linkSecret reads {"token": "..."} from r.
func linkSecret(w http.ResponseWriter, r *http.Request) (string, bool) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return "", false
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLinkBody)).Decode(&body); err != nil || body.Token == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {\"token\": \"...\"}")
		return "", false
	}
	return body.Token, true
}

// writeLinkInvalid answers for a link that is unknown, used or expired
// alike, so the answer says nothing about which.
func writeLinkInvalid(w http.ResponseWriter) {
	writeError(w, http.StatusGone, "link_invalid", "this approval link is invalid, already used or expired")
}

// peekApprovalLink shows the approval a link is for, without using it.
func (a *api) peekApprovalLink(w http.ResponseWriter, r *http.Request) {
	secret, ok := linkSecret(w, r)
	if !ok {
		return
	}
	id, err := a.store.ApprovalLinks().Peek(r.Context(), secret, a.now())
	if err == nil {
		var ap store.Approval
		if ap, err = a.store.Approvals().Get(r.Context(), id); err == nil {
			writeJSON(w, http.StatusOK, approvalJSON(ap))
			return
		}
	}
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrTokenUsed), errors.Is(err, store.ErrTokenExpired):
		writeLinkInvalid(w)
	default:
		a.log.ErrorContext(r.Context(), "peek approval link", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot read the approval link")
	}
}

// decideApprovalLink approves or denies through a link, spending it.
func (a *api) decideApprovalLink(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret, ok := linkSecret(w, r)
		if !ok {
			return
		}
		now := a.now()
		err := a.policy.DecideLink(r.Context(), remoteHost(r), approve, func(ctx context.Context) (string, error) {
			return a.store.ApprovalLinks().Use(ctx, secret, now)
		})
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, store.ErrUnavailable):
			writeUnavailable(w)
		case errors.Is(err, store.ErrApprovalClosed):
			writeError(w, http.StatusConflict, "closed", "the approval is no longer pending")
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrTokenUsed), errors.Is(err, store.ErrTokenExpired),
			errors.Is(err, store.ErrSchemaTooOld):
			writeLinkInvalid(w)
		case errors.Is(err, policy.ErrDenied):
			writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
		default:
			a.log.ErrorContext(r.Context(), "decide approval link", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot decide the approval")
		}
	}
}

// approvalJSON is ap as the API serves it.
func approvalJSON(ap store.Approval) ApprovalJSON {
	j := ApprovalJSON{
		ID: ap.ID, CreatedAt: ap.CreatedAt, ExpiresAt: ap.ExpiresAt, ActorKind: ap.ActorKind,
		ActorID: ap.ActorID, Action: ap.Action, Class: ap.Class, Target: ap.Target, Detail: ap.Detail,
		Status: ap.Status, DecidedBy: ap.DecidedBy,
	}
	if !ap.DecidedAt.IsZero() {
		j.DecidedAt = &ap.DecidedAt
	}
	return j
}
