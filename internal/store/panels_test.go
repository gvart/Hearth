// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPanelLinks(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()

	if err := s.Panels().Create(ctx, Panel{ID: "p1", Name: "Hall", Widgets: `[]`, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Panels().Create(ctx, Panel{ID: "p2", Name: "Kitchen", Widgets: `[]`, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	live, expiring, revoked, other := rand.Text(), rand.Text(), rand.Text(), rand.Text()
	for _, l := range []struct {
		link   PanelLink
		secret string
	}{
		{PanelLink{ID: "live", PanelID: "p1", CreatedAt: now}, live},
		{PanelLink{ID: "expiring", PanelID: "p1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, expiring},
		{PanelLink{ID: "revoked", PanelID: "p1", CreatedAt: now}, revoked},
		{PanelLink{ID: "other", PanelID: "p2", CreatedAt: now}, other},
	} {
		if err := s.Panels().CreateLink(ctx, l.link, l.secret); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Panels().RevokeLink(ctx, "p1", "revoked", now); err != nil {
		t.Fatal(err)
	}
	// A link is revoked only through its own panel.
	if err := s.Panels().RevokeLink(ctx, "p1", "other", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RevokeLink through another panel = %v, want ErrNotFound", err)
	}

	tests := []struct {
		name      string
		secret    string
		at        time.Time
		wantPanel string
		wantErr   error
	}{
		{"live", live, now, "p1", nil},
		{"live, much later", live, now.Add(1000 * time.Hour), "p1", nil},
		{"before expiry", expiring, now.Add(time.Hour - time.Millisecond), "p1", nil},
		{"at expiry", expiring, now.Add(time.Hour), "", ErrTokenExpired},
		{"revoked", revoked, now, "", ErrTokenRevoked},
		{"other panel", other, now, "p2", nil},
		{"unknown", rand.Text(), now, "", ErrNotFound},
		{"empty", "", now, "", ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _, err := s.Panels().CheckLink(ctx, tt.secret, tt.at)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CheckLink = %v, want %v", err, tt.wantErr)
			}
			if p.ID != tt.wantPanel {
				t.Errorf("panel = %q, want %q", p.ID, tt.wantPanel)
			}
		})
	}

	// Only the hash is stored.
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_links WHERE hash = ?`, []byte(live)).Scan(&n); err != nil || n != 0 {
		t.Errorf("secret stored in the clear: %d rows, %v", n, err)
	}
	var stored []byte
	if err := s.db.QueryRowContext(ctx, `SELECT hash FROM panel_links WHERE id = 'live'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if h := hashSecret(live); !bytes.Equal(stored, h[:]) {
		t.Error("stored hash is not the secret's SHA-256")
	}

	// Deleting a panel takes its links with it.
	if err := s.Panels().Delete(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Panels().CheckLink(ctx, live, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("CheckLink after the panel was deleted = %v, want ErrNotFound", err)
	}
	links, err := s.Panels().Links(ctx)
	if err != nil || len(links) != 1 || links[0].ID != "other" {
		t.Errorf("Links after delete = %+v, %v; want only other", links, err)
	}
}

func TestPanelsBeforeSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, panelsSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	var proposed []string
	s, err = Open(ctx, path, WithoutUpgrade(), WithApplier(func(s *Store) Applier {
		return ApplierFunc(func(ctx context.Context, cmd Command) (Result, error) {
			proposed = append(proposed, cmd.Op())
			return s.ApplyLocal(ctx, cmd)
		})
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if got, err := s.Panels().List(ctx); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v; want none", got, err)
	}
	if _, _, err := s.Panels().CheckLink(ctx, "x", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("CheckLink before the schema = %v, want ErrNotFound", err)
	}
	if err := s.Panels().Create(ctx, Panel{ID: "p", Name: "n", Widgets: `[]`}); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Create before the schema = %v, want ErrSchemaTooOld", err)
	}
	if err := s.Panels().CreateLink(ctx, PanelLink{ID: "l", PanelID: "p"}, "x"); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("CreateLink before the schema = %v, want ErrSchemaTooOld", err)
	}
	if len(proposed) != 0 {
		t.Errorf("proposed %v before the schema, want nothing", proposed)
	}
	for _, cmd := range []Command{
		CreatePanel{ID: "p", Name: "n", Widgets: `[]`},
		UpdatePanel{ID: "p", Name: "n", Widgets: `[]`},
		DeletePanel{ID: "p"},
		CreatePanelLink{ID: "l", PanelID: "p", Hash: []byte{1}},
		RevokePanelLink{PanelID: "p", ID: "l"},
	} {
		if _, err := s.ApplyLocal(ctx, cmd); !errors.Is(err, ErrSchemaTooOld) {
			t.Errorf("ApplyLocal(%s) before the schema = %v, want ErrSchemaTooOld", cmd.Op(), err)
		}
	}
}
