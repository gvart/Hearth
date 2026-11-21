// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/gvart/hearth/internal/store"
)

// countDevices opens the copy at path as a standalone store and counts its
// devices.
func countDevices(t *testing.T, path string) int {
	t.Helper()
	st, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	list, err := st.Devices().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return len(list)
}

// TestPullAllCopiesEveryShard: with 3 storage members and N = 2 no member
// holds every row, so a copy of one member's database is partial; PullAll
// makes it whole.
func TestPullAllCopiesEveryShard(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 2, "a", "b", "c")
	a := an.m("a")
	const total = 60
	for i := range total {
		if err := a.st.Devices().Upsert(ctx, device(fmt.Sprintf("dev%02d", i), "n")); err != nil {
			t.Fatal(err)
		}
	}
	apEventually(t, "every device listed", func() bool {
		list, err := a.st.Devices().List(ctx)
		return err == nil && len(list) == total
	})
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.db")
	if err := a.st.VacuumInto(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if got := countDevices(t, plain); got >= total {
		t.Fatalf("a's own database holds %d of %d devices: the test needs a partial member", got, total)
	}
	full := filepath.Join(dir, "full.db")
	if err := a.st.VacuumInto(ctx, full); err != nil {
		t.Fatal(err)
	}
	dst, err := store.Open(ctx, full, store.WithDigest())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.rep.PullAll(ctx, dst); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	if got := countDevices(t, full); got != total {
		t.Fatalf("complete copy holds %d devices, want %d", got, total)
	}
}

// TestPullAllRefusesAMissingShard: with the only replicas of some buckets
// down, the copy is refused, never written partial.
func TestPullAllRefusesAMissingShard(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 2, "a", "b", "c")
	a := an.m("a")
	an.setDown("b", true)
	an.setDown("c", true)
	path := filepath.Join(t.TempDir(), "copy.db")
	if err := a.st.VacuumInto(ctx, path); err != nil {
		t.Fatal(err)
	}
	dst, err := store.Open(ctx, path, store.WithDigest())
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	err = a.rep.PullAll(ctx, dst)
	if !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("PullAll with b and c down = %v, want ErrIncompleteSnapshot", err)
	}
	// One replica of every bucket is enough.
	an.setDown("b", false)
	if err := a.rep.PullAll(ctx, dst); err != nil {
		t.Fatalf("PullAll with c down: %v", err)
	}
}

// TestNodeSnapshot: an AP member's snapshot over its control socket path
// check: only a file inside the data dir is written.
func TestNodeSnapshot(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 1, apSpec{"a", storageMaster, storageMaster})
	a := c["a"]
	if err := a.st.Devices().Upsert(ctx, device("dev1", "n")); err != nil {
		t.Fatal(err)
	}
	if err := a.node.snapshotInDataDir(ctx, filepath.Join(t.TempDir(), "out.db")); err == nil {
		t.Fatal("a snapshot outside the data dir was written")
	}
	path := filepath.Join(a.dir, "copy.db")
	if err := a.node.snapshotInDataDir(ctx, path); err != nil {
		t.Fatal(err)
	}
	if got := countDevices(t, path); got != 1 {
		t.Fatalf("snapshot holds %d devices, want 1", got)
	}
}
