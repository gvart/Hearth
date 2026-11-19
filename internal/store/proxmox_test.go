// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A hub on an older binary halts on a command it cannot decode, so before the
// schema that added them these writes must never be proposed at all.
func TestProxmoxServersBeforeTheSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, proxmoxServersSchema-1); err != nil {
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

	if got, err := s.ProxmoxServers().List(ctx); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v; want none", got, err)
	}
	add := ProxmoxServer{ID: "a", Name: "rack", Sealed: []byte("x"), CreatedAt: time.Now()}
	if err := s.ProxmoxServers().Add(ctx, add); !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("Add before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
	if err := s.ProxmoxServers().Remove(ctx, "a"); !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("Remove before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
	if len(proposed) != 0 {
		t.Errorf("proposed %v before the schema, want nothing", proposed)
	}
}

func TestProxmoxServers(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	ps := s.ProxmoxServers()
	now := time.UnixMilli(1_700_000_000_000).UTC()

	if got, err := ps.List(ctx); err != nil || len(got) != 0 {
		t.Fatalf("List on a new store = %v, %v; want none", got, err)
	}
	for _, c := range []ProxmoxServer{
		{ID: "b", Name: "rack", Sealed: []byte("sealed-b"), CreatedAt: now},
		{ID: "a", Name: "attic", Sealed: []byte("sealed-a"), CreatedAt: now},
	} {
		if err := ps.Add(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := ps.Add(ctx, ProxmoxServer{ID: "c", Name: "attic", Sealed: []byte("x"), CreatedAt: now}); !IsDomainError(err) {
		t.Errorf("Add with a taken name = %v, want a constraint violation", err)
	}
	if err := ps.Add(ctx, ProxmoxServer{ID: "d", Name: "empty", CreatedAt: now}); err == nil {
		t.Error("Add without a sealed connection succeeded")
	}
	got, err := ps.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "attic" || got[1].Name != "rack" ||
		!bytes.Equal(got[0].Sealed, []byte("sealed-a")) || !got[0].CreatedAt.Equal(now) {
		t.Fatalf("List = %+v", got)
	}
	if err := ps.Remove(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := ps.Remove(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Remove = %v, want ErrNotFound", err)
	}
}
