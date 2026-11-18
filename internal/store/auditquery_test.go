// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"slices"
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
