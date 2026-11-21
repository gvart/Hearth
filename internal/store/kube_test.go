// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestKubeClusters(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	kc := s.KubeClusters()
	now := time.UnixMilli(1_700_000_000_000).UTC()

	if got, err := kc.List(ctx); err != nil || len(got) != 0 {
		t.Fatalf("List on a new store = %v, %v; want none", got, err)
	}
	for _, c := range []KubeCluster{
		{ID: "b", Name: "talos", Sealed: []byte("sealed-b"), CreatedAt: now},
		{ID: "a", Name: "kind", Sealed: []byte("sealed-a"), CreatedAt: now},
	} {
		if err := kc.Add(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := kc.Add(ctx, KubeCluster{ID: "c", Name: "kind", Sealed: []byte("x"), CreatedAt: now}); !IsDomainError(err) {
		t.Errorf("Add with a taken name = %v, want a constraint violation", err)
	}
	if err := kc.Add(ctx, KubeCluster{ID: "d", Name: "empty", CreatedAt: now}); err == nil {
		t.Error("Add without a kubeconfig succeeded")
	}
	got, err := kc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "kind" || got[1].Name != "talos" ||
		!bytes.Equal(got[0].Sealed, []byte("sealed-a")) || !got[0].CreatedAt.Equal(now) {
		t.Fatalf("List = %+v", got)
	}
	if err := kc.Remove(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := kc.Remove(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove of a removed cluster = %v, want ErrNotFound", err)
	}
	if got, _ := kc.List(ctx); len(got) != 1 || got[0].ID != "b" {
		t.Errorf("List after Remove = %+v", got)
	}
}

// A hub runs on the cluster's schema until every hub of the cluster is upgraded: before
// schema 8 there are no Kubernetes clusters and none can be added.
func TestKubeClustersBeforeTheirSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, kubeClustersSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	kc := s.KubeClusters()

	if got, err := kc.List(ctx); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v; want none", got, err)
	}
	c := KubeCluster{ID: "a", Name: "kind", Sealed: []byte("x"), CreatedAt: time.Now()}
	if err := kc.Add(ctx, c); !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("Add before the schema = %v, want ErrSchemaTooOld", err)
	}
	if err := s.migrateTo(ctx, kubeClustersSchema); err != nil {
		t.Fatal(err)
	}
	if err := kc.Add(ctx, c); err != nil {
		t.Errorf("Add after the migrate: %v", err)
	}
}
