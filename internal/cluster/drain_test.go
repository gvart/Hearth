// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"errors"
	"fmt"
	"testing"
)

// TestDrainCompletesOnlyWithEveryCopy: a storage member being demoted keeps
// the role while a future owner of its rows is down (killed mid-drain), and
// completes once that owner is back and holds every row.
func TestDrainCompletesOnlyWithEveryCopy(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	for i := range 40 {
		id := fmt.Sprintf("dev-%02d", i)
		if err := an.m("a").st.Devices().Upsert(ctx, device(id, id)); err != nil {
			t.Fatal(err)
		}
	}
	// Writes reach their second replica in the background: let them land.
	apEventually(t, "every device on its two replicas", func() bool {
		for i := range 40 {
			id, copies := fmt.Sprintf("dev-%02d", i), 0
			for _, m := range ids {
				if _, ok := localDevice(t, an.m(m), id); ok {
					copies++
				}
			}
			if copies < 2 {
				return false
			}
		}
		return true
	})
	// The future owners of c's rows: a and b. Kill b in the middle.
	an.setDown("b", true)
	p, err := an.m("c").rep.Drain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.Total == 0 {
		t.Fatal("c holds no rows: the test needs some")
	}
	if p.Complete() {
		t.Fatalf("drain complete with b down: %+v", p)
	}
	if p.Waiting != "b" {
		t.Fatalf("waiting for %q, want b", p.Waiting)
	}
	an.setDown("b", false)
	p, err = an.m("c").rep.Drain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Complete() || p.Percent() != 100 {
		t.Fatalf("drain not complete with every member up: %+v", p)
	}
	// With N=2 and two members left, each holds every row.
	for i := range 40 {
		id := fmt.Sprintf("dev-%02d", i)
		for _, m := range []string{"a", "b"} {
			if _, ok := localDevice(t, an.m(m), id); !ok {
				t.Fatalf("%s lacks %s after the drain", m, id)
			}
		}
	}
}

// TestDrainRefusesTheLastStorageMember: no other storage member, no drain.
func TestDrainRefusesTheLastStorageMember(t *testing.T) {
	an := newAPNet(t, 1, "a")
	if err := an.m("a").st.Devices().Upsert(t.Context(), device("d", "d")); err != nil {
		t.Fatal(err)
	}
	if _, err := an.m("a").rep.Drain(t.Context()); !errors.Is(err, ErrLastStorage) {
		t.Fatalf("Drain = %v, want ErrLastStorage", err)
	}
}
