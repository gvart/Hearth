// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestNetEdgesReplace(t *testing.T) {
	ctx := t.Context()
	var proposed int
	s, err := Open(ctx, filepath.Join(t.TempDir(), "hearth.db"), WithApplier(func(s *Store) Applier {
		return ApplierFunc(func(ctx context.Context, cmd Command) (Result, error) {
			proposed++
			return s.ApplyLocal(ctx, cmd)
		})
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	at := time.UnixMilli(1_700_000_000_000).UTC()

	if got, err := s.NetEdges().Get(ctx, "pi"); err != nil || len(got.Edges) != 0 || !got.UpdatedAt.IsZero() {
		t.Fatalf("Get before any report = %+v, %v; want none", got, err)
	}

	nb := NetEdge{Kind: EdgeNeighbor, IP: "192.0.2.1", MAC: "aa:bb:cc:dd:ee:01"}
	out := NetEdge{Kind: EdgeConnection, IP: "192.0.2.10", Port: 7443, Count: 2}
	in := NetEdge{Kind: EdgeConnection, IP: "192.0.2.10", Port: 22, Inbound: true, Count: 1}
	report := []NetEdge{out, nb, in, nb} // unsorted, with a duplicate
	changed, err := s.NetEdges().Replace(ctx, "pi", at, report)
	if err != nil || !changed {
		t.Fatalf("first Replace = %v, %v; want a write", changed, err)
	}
	want := []NetEdge{in, out, nb}
	got, err := s.NetEdges().Get(ctx, "pi")
	if err != nil || !slices.Equal(got.Edges, want) || !got.UpdatedAt.Equal(at) {
		t.Fatalf("Get = %+v, %v; want %+v at %v", got, err, want, at)
	}

	// The same edges in another order write nothing and keep the time.
	changed, err = s.NetEdges().Replace(ctx, "pi", at.Add(time.Minute), []NetEdge{nb, in, out})
	if err != nil || changed || proposed != 1 {
		t.Fatalf("unchanged Replace = %v, %v (%d proposals); want no write", changed, err, proposed)
	}
	if got, _ := s.NetEdges().Get(ctx, "pi"); !got.UpdatedAt.Equal(at) {
		t.Errorf("UpdatedAt after an unchanged report = %v, want %v", got.UpdatedAt, at)
	}

	// Another device's edges are its own.
	if _, err := s.NetEdges().Replace(ctx, "nas", at, []NetEdge{nb}); err != nil {
		t.Fatal(err)
	}

	// A changed count replaces the set; an empty report clears it.
	out.Count = 3
	later := at.Add(2 * time.Minute)
	if changed, err := s.NetEdges().Replace(ctx, "pi", later, []NetEdge{out}); err != nil || !changed {
		t.Fatalf("changed Replace = %v, %v", changed, err)
	}
	if got, _ := s.NetEdges().Get(ctx, "pi"); !slices.Equal(got.Edges, []NetEdge{out}) || !got.UpdatedAt.Equal(later) {
		t.Errorf("after a change = %+v, want only %+v at %v", got, out, later)
	}
	if changed, err := s.NetEdges().Replace(ctx, "pi", later, nil); err != nil || !changed {
		t.Fatalf("empty Replace = %v, %v", changed, err)
	}
	if got, _ := s.NetEdges().Get(ctx, "pi"); len(got.Edges) != 0 {
		t.Errorf("after an empty report = %+v, want none", got)
	}
	if got, _ := s.NetEdges().Get(ctx, "nas"); !slices.Equal(got.Edges, []NetEdge{nb}) {
		t.Errorf("nas = %+v, want its own neighbour", got)
	}
}

// Before the schema that added the table no edge is listed, and no write is
// proposed.
func TestNetEdgesBeforeTheSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, netEdgesSchema-1); err != nil {
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

	if got, err := s.NetEdges().Get(ctx, "pi"); err != nil || len(got.Edges) != 0 {
		t.Errorf("Get before the schema = %+v, %v; want none", got, err)
	}
	_, err = s.NetEdges().Replace(ctx, "pi", time.Now(), []NetEdge{{Kind: EdgeNeighbor, IP: "192.0.2.1", MAC: "aa:bb:cc:dd:ee:01"}})
	if !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Replace before the schema = %v, want ErrSchemaTooOld", err)
	}
	if len(proposed) != 0 {
		t.Errorf("proposed %v before the schema, want nothing", proposed)
	}
}
