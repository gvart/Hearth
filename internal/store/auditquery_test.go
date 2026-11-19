// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAuditQuery(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	rows := []AuditEntry{
		{ActorKind: "web", ActorID: "192.0.2.1", Action: "token.create", Decision: "allow"},
		{ActorKind: "admin", ActorID: "root", Action: "device.revoke", Target: "pi", Decision: "deny"},
		{ActorKind: "automation", ActorID: "fix-dns", Action: "automation.restart", Target: "pi.lan", Decision: "allow"},
		{ActorKind: "automation", ActorID: "fix-dns", Action: "automation.exec", Target: "nas", Decision: "confirm"},
		{ActorKind: "web", ActorID: "192.0.2.7", Action: "admin.login", Decision: "deny"},
	}
	for i, e := range rows {
		e.TS = base.Add(time.Duration(i) * time.Minute)
		if _, err := s.Audit().Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(es []AuditEntry) []int64 {
		var out []int64
		for _, e := range es {
			out = append(out, e.ID)
		}
		return out
	}
	tests := []struct {
		name  string
		f     AuditFilter
		limit int
		want  []int64
	}{
		{"all, newest first", AuditFilter{}, 10, []int64{5, 4, 3, 2, 1}},
		{"limit", AuditFilter{}, 2, []int64{5, 4}},
		{"actor kind", AuditFilter{ActorKind: "web"}, 10, []int64{5, 1}},
		{"actor id part", AuditFilter{ActorID: "192.0.2"}, 10, []int64{5, 1}},
		{"actor kind and id", AuditFilter{ActorKind: "automation", ActorID: "fix"}, 10, []int64{4, 3}},
		{"actions", AuditFilter{Actions: []string{"automation.exec", "device.revoke"}}, 10, []int64{4, 2}},
		{"targets", AuditFilter{Targets: []string{"pi", "pi.lan"}}, 10, []int64{3, 2}},
		{"decision", AuditFilter{Decision: "deny"}, 10, []int64{5, 2}},
		{"since", AuditFilter{Since: base.Add(3 * time.Minute)}, 10, []int64{5, 4}},
		{"until", AuditFilter{Until: base.Add(time.Minute)}, 10, []int64{1}},
		{"before cursor", AuditFilter{Before: 3}, 10, []int64{2, 1}},
		{"nothing", AuditFilter{ActorKind: "hub"}, 10, nil},
		{"an injection attempt is a value", AuditFilter{ActorID: "' OR 1=1 --"}, 10, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Audit().Query(ctx, tt.f, tt.limit)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ids(got), tt.want) {
				t.Errorf("ids = %v, want %v", ids(got), tt.want)
			}
		})
	}
	if _, err := s.Audit().Query(ctx, AuditFilter{}, 0); err == nil {
		t.Error("Query with limit 0 succeeded")
	}
}

// TestAuditQueryOneRowPerAction: the entry written before an action and the
// one reporting its outcome read as one row, in the place of the first.
func TestAuditQueryOneRowPerAction(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	for i, e := range []AuditEntry{
		{Action: "device.revoke", Result: "started", Detail: json.RawMessage(`{"n":1,"audit_op":"finished"}`)}, // 1
		{Action: "token.create", Result: "ok", Detail: json.RawMessage(`{"old":true}`)},                        // 2: written before outcomes existed
		{Action: "device.exec", Result: "started", Detail: json.RawMessage(`{"audit_op":"crashed"}`)},          // 3: never reports
		{Action: "device.read", Result: "read allowed", Detail: json.RawMessage(`{"audit_op":"read"}`)},        // 4
		{Action: "kube.read", Result: "read allowed", Detail: json.RawMessage(`{"audit_op":"failed"}`)},        // 5
		{Action: "kube.read", Result: "error: boom", Detail: json.RawMessage(`{"audit_outcome_of":"failed"}`)}, // 6
		{Action: "device.revoke", Result: "ok", Detail: json.RawMessage(`{"n":2,"audit_outcome_of":"finished"}`)},
	} {
		e.ActorKind, e.ActorID, e.Decision, e.TS = "admin", "root", "allow", base.Add(time.Duration(i)*time.Minute)
		if _, err := s.Audit().Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		id             int64
		result, detail string
	}{
		{5, "error: boom", `{}`},
		{4, "read allowed", `{}`},
		{3, "started", `{}`},
		{2, "ok", `{"old":true}`},
		{1, "ok", `{"n":2}`},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if e := got[i]; e.ID != w.id || e.Result != w.result || string(e.Detail) != w.detail {
			t.Errorf("row %d = id %d %q %s, want id %d %q %s", i, e.ID, e.Result, e.Detail, w.id, w.result, w.detail)
		}
	}
	if !got[4].TS.Equal(base) {
		t.Errorf("ts = %v, want when the action started (%v)", got[4].TS, base)
	}

	// An outcome on a newer page than its action still reaches it, and
	// takes no place on a page.
	page, err := s.Audit().Query(ctx, AuditFilter{Before: 2}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != 1 || page[0].Result != "ok" {
		t.Errorf("older page = %+v, want action 1 with its outcome", page)
	}
}

// nestedJSON returns a JSON array nested depth levels deep.
func nestedJSON(depth int) json.RawMessage {
	return json.RawMessage(strings.Repeat("[", depth) + strings.Repeat("]", depth))
}

// TestAuditAppendLimitsDetailDepth: a detail nested too deep for the log's
// readers is refused when written.
func TestAuditAppendLimitsDetailDepth(t *testing.T) {
	tests := []struct {
		name    string
		detail  json.RawMessage
		wantErr bool
	}{
		{"at the limit", nestedJSON(maxAuditDetailDepth), false},
		{"over the limit", nestedJSON(maxAuditDetailDepth + 1), true},
		{"what SQLite cannot parse", nestedJSON(1001), true},
		{"objects count too", json.RawMessage(strings.Repeat(`{"a":`, maxAuditDetailDepth+1) + "1" + strings.Repeat("}", maxAuditDetailDepth+1)), true},
		{"brackets in a string do not", json.RawMessage(`{"a":"` + strings.Repeat("[", maxAuditDetailDepth+1) + `"}`), false},
		{"an escaped quote does not end a string", json.RawMessage(`{"a":"\"` + strings.Repeat("[", maxAuditDetailDepth+1) + `"}`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := openTest(t).Audit().Append(t.Context(), AuditEntry{
				ActorKind: "admin", ActorID: "root", Action: "device.revoke", Decision: "allow", Detail: tt.detail,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("Append = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

// TestAuditQueryReadsARowSQLiteCannotParse: a detail SQLite's JSON functions
// reject, such as one written before the depth limit, must not take the rest
// of the log down with it.
func TestAuditQueryReadsARowSQLiteCannotParse(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	add := func(action, result, detail string) {
		t.Helper()
		// Through the applier, as a row already in the replicated log arrives.
		if _, err := s.apply(ctx, AppendAudit{
			TS: toMillis(time.Now()), ActorKind: "admin", ActorID: "root", Action: action,
			Decision: "allow", Result: result, Detail: detail,
		}); err != nil {
			t.Fatal(err)
		}
	}
	deep := string(nestedJSON(1001))
	add("device.revoke", "started", `{"audit_op":"x"}`)
	add("device.exec", "ok", deep)
	add("device.revoke", "ok", `{"audit_outcome_of":"x"}`)

	got, err := s.Audit().List(ctx, 10)
	if err != nil {
		t.Fatalf("the log is unreadable: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(got), got)
	}
	if got[0].Action != "device.exec" || string(got[0].Detail) != deep {
		t.Errorf("row = %s, want the deep row as written", got[0].Action)
	}
	if got[1].Action != "device.revoke" || got[1].Result != "ok" {
		t.Errorf("row = %+v, want the action folded with its outcome", got[1])
	}
}

// TestAuditQueryDetailCannotHideARow: only a top-level key marks an outcome,
// so a value someone controls, such as a hostname, cannot hide its own entry.
func TestAuditQueryDetailCannotHideARow(t *testing.T) {
	s := openTest(t)
	for _, detail := range []string{
		`{"hostname":"audit_outcome_of"}`,
		`{"hostname":"\"audit_outcome_of\":\"x\""}`,
		`{"nested":{"audit_outcome_of":"x"}}`,
	} {
		if _, err := s.Audit().Append(t.Context(), AuditEntry{
			ActorKind: "token", ActorID: "t", Action: "device.enroll", Decision: "allow", Result: "ok", Detail: json.RawMessage(detail),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("got %d rows, want all 3: %+v", len(got), got)
	}
}
