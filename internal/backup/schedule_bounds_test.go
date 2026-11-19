// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"slices"
	"testing"
	"time"
)

// TestUntilDueIsBoundedByTheInterval: a backup dated in the future, from a
// clock that was ahead, does not put the schedule off past one interval.
func TestUntilDueIsBoundedByTheInterval(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	b := newMemBucket("hearth/hearth-20361119T120000Z.hbk")
	s, _, _ := newScheduler(t, b, nil, now)
	if got := s.untilDue(t.Context()); got != s.cfg.Interval {
		t.Fatalf("untilDue = %v, want the interval %v", got, s.cfg.Interval)
	}
}

// stallingList is a bucket whose listing never answers.
type stallingList struct{ *memBucket }

func (stallingList) List(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestUntilDueGivesUpOnAStalledListing(t *testing.T) {
	s, _, _ := newScheduler(t, stallingList{newMemBucket()}, nil, time.Now())
	s.cfg.runTime = 200 * time.Millisecond
	done := make(chan time.Duration, 1)
	go func() { done <- s.untilDue(t.Context()) }()
	select {
	case got := <-done:
		if got != 0 {
			t.Fatalf("untilDue = %v, want 0: the backup runs and reports the bucket", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("untilDue waited on a listing that never answers")
	}
}

// TestPruneKeepsTheNewUploadAfterTheClockWentBack: the backup just taken
// sorts as the oldest when the clock went back, and stays all the same.
func TestPruneKeepsTheNewUploadAfterTheClockWentBack(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	b := newMemBucket(
		"hearth/hearth-20261116T120000Z.hbk", "hearth/hearth-20261117T120000Z.hbk",
		"hearth/hearth-20261118T120000Z.hbk", "hearth/hearth-20261119T120000Z.hbk",
	)
	s, _, _ := newScheduler(t, b, nil, now) // Keep 3
	if err := s.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"hearth/hearth-20261101T120000Z.hbk", "hearth/hearth-20261118T120000Z.hbk", "hearth/hearth-20261119T120000Z.hbk",
	}
	if got := b.keys(); !slices.Equal(got, want) {
		t.Fatalf("bucket holds %q\nwant %q", got, want)
	}
}

// sloppyList is a bucket that lists every key, whatever the prefix asked.
type sloppyList struct{ *memBucket }

func (b sloppyList) List(ctx context.Context, _ string) ([]string, error) {
	return b.memBucket.List(ctx, "")
}

// TestPruneOnlyUnderThePrefix: a backup-like key outside the prefix is never
// pruned, even when the store lists it.
func TestPruneOnlyUnderThePrefix(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	outside := "hearth-20200101T000000Z.hbk"
	b := newMemBucket(outside, "hearth/hearth-20261117T120000Z.hbk", "hearth/hearth-20261118T120000Z.hbk",
		"hearth/hearth-20261118T130000Z.hbk")
	s, _, _ := newScheduler(t, sloppyList{b}, nil, now)
	if err := s.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(b.keys(), outside) {
		t.Fatalf("pruned %s, outside the prefix: bucket holds %q", outside, b.keys())
	}
	if slices.Contains(b.keys(), "hearth/hearth-20261117T120000Z.hbk") {
		t.Fatalf("the oldest backup under the prefix stayed: %q", b.keys())
	}
}
