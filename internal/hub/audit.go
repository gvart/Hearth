// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// defaultAuditPage and maxAuditPage bound GET /api/v1/audit's limit.
	defaultAuditPage = 100
	maxAuditPage     = 500
)

// AuditEntryJSON is one audit log entry, as the API serves it.
type AuditEntryJSON struct {
	ID        int64     `json:"id"`
	TS        time.Time `json:"ts"`
	ActorKind string    `json:"actor_kind"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	// Class is the action's policy class; empty for an unknown action.
	Class    string          `json:"class"`
	Target   string          `json:"target"`
	Decision string          `json:"decision"`
	Result   string          `json:"result"`
	Detail   json.RawMessage `json:"detail"`
}

// AuditPageJSON is a page of the audit log, newest first. NextBefore, when
// set, is the before= cursor of the next, older page. A hub of an AP
// cluster, where an entry id (its HLC) is not unique, sets NextCursor
// instead: an opaque before= cursor, the entry's global id.
type AuditPageJSON struct {
	Entries    []AuditEntryJSON `json:"entries"`
	NextBefore int64            `json:"next_before,omitempty"`
	NextCursor string           `json:"next_cursor,omitempty"`
	// Actions are every action policy knows, for filters.
	Actions []string `json:"actions"`
}

// listAudit serves the audit log, filtered by the query parameters
// actor_kind, actor (part of the actor id), action, class, decision, device
// (its id: entries targeting its id, name or hostname), since and until
// (RFC 3339), before (a cursor) and limit.
func (a *api) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{ActorKind: q.Get("actor_kind"), ActorID: q.Get("actor"), Decision: q.Get("decision")}
	bad := func(msg string) { writeError(w, http.StatusBadRequest, "bad_request", msg) }

	// An action and a class both narrow the set of actions; an empty set
	// matches nothing.
	actions := policy.Actions()
	if v := q.Get("action"); v != "" {
		actions = []policy.Action{policy.Action(v)}
	}
	if v := q.Get("class"); v != "" {
		switch c := policy.Class(v); c {
		case policy.Read, policy.Safe, policy.Dangerous:
			actions = slices.DeleteFunc(actions, func(a policy.Action) bool {
				got, _ := policy.ClassOf(a)
				return got != c
			})
		default:
			bad("class must be read, safe or dangerous")
			return
		}
	}
	if q.Get("action") != "" || q.Get("class") != "" {
		f.Actions = []string{}
		for _, a := range actions {
			f.Actions = append(f.Actions, string(a))
		}
		if len(f.Actions) == 0 {
			writeJSON(w, http.StatusOK, AuditPageJSON{Entries: []AuditEntryJSON{}, Actions: allActions()})
			return
		}
	}
	for _, p := range []struct {
		name string
		to   *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := q.Get(p.name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				bad(p.name + " must be an RFC 3339 time")
				return
			}
			*p.to = t
		}
	}
	if v := q.Get("before"); v != "" && a.store.Sharded() {
		if store.CheckAuditCursor(v) != nil {
			bad("before must be a next_cursor of this log")
			return
		}
		f.BeforeCursor = v
	} else if v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			bad("before must be a positive entry id")
			return
		}
		f.Before = n
	}
	limit := defaultAuditPage
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > maxAuditPage {
			bad("limit must be between 1 and 500")
			return
		}
		limit = n
	}
	if id := q.Get("device"); id != "" {
		d, err := a.store.Devices().Get(r.Context(), id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			f.Targets = []string{id}
		case err != nil:
			a.log.ErrorContext(r.Context(), "list audit", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot read the audit log")
			return
		default:
			// Automations name a device by id, name or hostname.
			for _, t := range []string{d.ID, d.Name, d.Hostname} {
				if t != "" && !slices.Contains(f.Targets, t) {
					f.Targets = append(f.Targets, t)
				}
			}
		}
	}

	// One more than asked tells whether an older page exists.
	entries, err := a.store.Audit().Query(r.Context(), f, limit+1)
	if err != nil {
		a.log.ErrorContext(r.Context(), "list audit", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot read the audit log")
		return
	}
	page := AuditPageJSON{Entries: make([]AuditEntryJSON, 0, min(len(entries), limit)), Actions: allActions()}
	if len(entries) > limit {
		entries = entries[:limit]
		if last := entries[limit-1]; last.Cursor != "" {
			page.NextCursor = last.Cursor
		} else {
			page.NextBefore = last.ID
		}
	}
	for _, e := range entries {
		class, _ := policy.ClassOf(policy.Action(e.Action))
		page.Entries = append(page.Entries, AuditEntryJSON{
			ID: e.ID, TS: e.TS, ActorKind: e.ActorKind, ActorID: e.ActorID, Action: e.Action, Class: string(class),
			Target: e.Target, Decision: e.Decision, Result: e.Result, Detail: e.Detail,
		})
	}
	writeJSON(w, http.StatusOK, page)
}

func allActions() []string {
	var out []string
	for _, a := range policy.Actions() {
		out = append(out, string(a))
	}
	return out
}
