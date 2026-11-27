// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"testing"
	"time"
)

// TestGrantsResetOnUpgrade: a database that was a cluster's (the hub
// certificates of two hubs) loses its sessions, MCP and dashboard tokens and
// panel links as it is migrated past sessionEpochSchema, once: a master's
// copy from before may lack a revocation (#384). A single hub's keeps them,
// and so does a database already migrated, a restored archive's included.
func TestGrantsResetOnUpgrade(t *testing.T) {
	ctx := t.Context()
	cases := []struct {
		name  string
		hubs  []string
		after bool // grants left
	}{
		{"single hub", []string{"a"}, true},
		{"single hub, its certificate renewed", []string{"a", "a"}, true},
		{"cluster", []string{"a", "b"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openAtSchema(t, sessionEpochSchema-1)
			for i, id := range tc.hubs {
				if err := s.Hubs().Record(ctx, HubCert{Serial: string(rune('1' + i)), NodeID: id}); err != nil {
					t.Fatal(err)
				}
			}
			grant(t, s)
			path := s.path
			_ = s.Close()
			s, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			if got, want := grants(t, s), map[bool]int{true: 4, false: 0}[tc.after]; got != want {
				t.Fatalf("grants after the upgrade: %d, want %d", got, want)
			}
			// Once: those created since stay.
			grant(t, s)
			_ = s.Close()
			if s, err = Open(ctx, path); err != nil {
				t.Fatal(err)
			}
			if got, want := grants(t, s), map[bool]int{true: 8, false: 4}[tc.after]; got != want {
				t.Fatalf("grants after a second start: %d, want %d", got, want)
			}
		})
	}
}

// grant writes a session, an MCP and a dashboard token, and a panel with a
// share link.
func grant(t *testing.T, s *Store) {
	t.Helper()
	ctx, now := t.Context(), time.Now()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM panels`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	id := string(rune('a' + n)) // panels are kept
	if err := s.Admin().CreateSession(ctx, "session-"+id, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.MCPTokens().Create(ctx, "mcp-"+id, "mcp-"+id, "read", now); err != nil {
		t.Fatal(err)
	}
	if err := s.DashboardTokens().Create(ctx, DashboardToken{ID: id, Name: id, CreatedAt: now}, "dash-"+id); err != nil {
		t.Fatal(err)
	}
	if err := s.Panels().Create(ctx, Panel{ID: id, Name: id, Widgets: "[]", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Panels().CreateLink(ctx, PanelLink{ID: id, PanelID: id, CreatedAt: now}, "link-"+id); err != nil {
		t.Fatal(err)
	}
}

// grants counts the live sessions, MCP and dashboard tokens and panel links.
func grants(t *testing.T, s *Store) int {
	t.Helper()
	n := 0
	for _, table := range []string{"sessions", "mcp_tokens", "dashboard_tokens", "panel_links"} {
		var k int
		if err := s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table+` WHERE _deleted = 0`).Scan(&k); err != nil {
			t.Fatal(err)
		}
		n += k
	}
	return n
}
