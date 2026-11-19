// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func testRunbookRun(id string, at time.Time) RunbookRun {
	return RunbookRun{
		ID: id, RunbookID: "rb", Status: "running", StartedBy: "web/10.0.0.1", StartedAt: at, UpdatedAt: at,
		Source: []byte("sealed"), State: json.RawMessage(`{"cursor":0}`),
	}
}

func TestRunbookRunSaveIsCompareAndSwap(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	runs := s.RunbookRuns()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := runs.Create(ctx, testRunbookRun("r1", now)); err != nil {
		t.Fatal(err)
	}
	got, err := runs.Get(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || string(got.Source) != "sealed" || got.StartedBy != "web/10.0.0.1" || !got.FinishedAt.IsZero() {
		t.Fatalf("run = %+v", got)
	}

	first := got
	first.Status, first.State = "failed", json.RawMessage(`{"cursor":1}`)
	v, err := runs.Save(ctx, first)
	if err != nil || v != 2 {
		t.Fatalf("Save = %d, %v", v, err)
	}
	// A second writer from the same version loses, and changes nothing.
	second := got
	second.Status = "succeeded"
	_, err = runs.Save(ctx, second)
	if !errors.Is(err, ErrRunbookRunConflict) || !IsDomainError(err) {
		t.Fatalf("stale Save = %v, want a domain ErrRunbookRunConflict", err)
	}
	cur, err := runs.Get(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if cur.Status != "failed" || cur.Version != 2 || string(cur.State) != `{"cursor":1}` {
		t.Errorf("after the lost write: %+v", cur)
	}
	missing := got
	missing.ID = "nope"
	if _, err := runs.Save(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("Save of an unknown run = %v", err)
	}
	if _, err := runs.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get of an unknown run = %v", err)
	}
}

func TestRunbookRunListAndOpen(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	runs := s.RunbookRuns()
	now := time.Now().UTC().Truncate(time.Millisecond)
	for i, id := range []string{"a", "b", "c"} {
		if err := runs.Create(ctx, testRunbookRun(id, now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	b, err := runs.Get(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	b.Status, b.FinishedAt = "succeeded", now
	if _, err := runs.Save(ctx, b); err != nil {
		t.Fatal(err)
	}

	listed, err := runs.List(ctx, "", 2)
	if err != nil || len(listed) != 2 || listed[0].ID != "c" || listed[1].ID != "b" || len(listed[0].Source) != 0 {
		t.Errorf("List = %+v, %v", listed, err)
	}
	if other, err := runs.List(ctx, "other", 10); err != nil || len(other) != 0 {
		t.Errorf("List of another runbook = %+v, %v", other, err)
	}
	open, err := runs.Open(ctx)
	if err != nil || len(open) != 2 || open[0].ID != "a" || open[1].ID != "c" {
		t.Errorf("Open = %+v, %v", open, err)
	}
}

func TestRunbookRunsPruneOnlyFinishedRuns(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	runs := s.RunbookRuns()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := runs.Create(ctx, testRunbookRun("unfinished", now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	for i := range RunbookRunsKept + 5 {
		id := fmt.Sprintf("r%03d", i)
		if err := runs.Create(ctx, testRunbookRun(id, now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
		r, err := runs.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		r.Status, r.FinishedAt = "succeeded", now
		if _, err := runs.Save(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// Pruning happens as a run is created.
	if err := runs.Create(ctx, testRunbookRun("last", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	all, err := runs.List(ctx, "rb", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != RunbookRunsKept+2 {
		t.Errorf("%d runs kept, want %d", len(all), RunbookRunsKept+2)
	}
	if _, err := runs.Get(ctx, "unfinished"); err != nil {
		t.Errorf("an unfinished run was pruned: %v", err)
	}
	if _, err := runs.Get(ctx, "r000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the oldest finished run was kept: %v", err)
	}
}

func TestRunbookRunCommandsReplay(t *testing.T) {
	src := openTest(t)
	ctx := t.Context()
	var log []Command
	apply := func(c Command) error {
		b, err := EncodeCommand(c)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecodeCommand(b)
		if err != nil {
			t.Fatal(err)
		}
		log = append(log, dec)
		_, err = src.ApplyLocal(ctx, dec)
		return err
	}
	if err := apply(CreateRunbookRun{
		ID: "r", RunbookID: "rb", Status: "running", StartedBy: "web/x", StartedAt: 1,
		Source: []byte{0, 1, 2}, State: "{}", Keep: 10,
	}); err != nil {
		t.Fatal(err)
	}
	if err := apply(SaveRunbookRun{ID: "r", Version: 1, Status: "failed", UpdatedAt: 2, State: `{"a":1}`}); err != nil {
		t.Fatal(err)
	}
	if err := apply(SaveRunbookRun{ID: "r", Version: 1, Status: "lost", UpdatedAt: 3, State: "{}"}); !errors.Is(err, ErrRunbookRunConflict) {
		t.Fatalf("stale save = %v", err)
	}

	dst := openTest(t)
	for _, c := range log {
		if _, err := dst.ApplyLocal(ctx, c); err != nil && !IsDomainError(err) {
			t.Fatal(err)
		}
	}
	a, err := src.RunbookRuns().Get(ctx, "r")
	if err != nil {
		t.Fatal(err)
	}
	b, err := dst.RunbookRuns().Get(ctx, "r")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != "failed" || a.Status != b.Status || a.Version != b.Version || string(a.State) != string(b.State) ||
		string(a.Source) != string(b.Source) {
		t.Errorf("replayed run differs: %+v vs %+v", a, b)
	}
}

func TestRunbookRunsBeforeTheirSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, runbookRunsSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	runs := s.RunbookRuns()
	if got, err := runs.Open(ctx); err != nil || len(got) != 0 {
		t.Errorf("Open before the schema = %v, %v", got, err)
	}
	if got, err := runs.List(ctx, "", 10); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v", got, err)
	}
	if _, err := runs.Get(ctx, "r"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get before the schema = %v", err)
	}
	err = runs.Create(ctx, testRunbookRun("r", time.Now()))
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("Create before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
}
