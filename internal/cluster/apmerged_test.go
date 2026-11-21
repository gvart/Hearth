// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// TestMergeObservedOnTheOtherMaster: a device written on one master reaches
// the other's merge observer (store.ObserveMerges), which the hub turns into
// UI events there (#266); the writer's own observer hears nothing of it.
func TestMergeObservedOnTheOtherMaster(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := startAPTestNode(t, ca, apSpec{"a", storageMaster, storageMaster}, 2, "")
	b := startAPTestNode(t, ca, apSpec{"b", storageMaster, storageMaster}, 2, a.addr)
	waitUntil(t, 10*time.Second, "a and b to see each other", func() bool {
		return a.memberOn(b).State == MemberAlive && b.memberOn(a).State == MemberAlive
	})
	var (
		mu   sync.Mutex
		told = map[string][]string{}
	)
	observe := func(id string) func([]store.MergedRow) {
		return func(rows []store.MergedRow) {
			mu.Lock()
			defer mu.Unlock()
			for _, r := range rows {
				if r.Table == "devices" {
					told[id] = append(told[id], r.Key[0].(string)) //nolint:forcetypeassert // a device key is its id
				}
			}
		}
	}
	a.st.ObserveMerges(observe("a"))
	b.st.ObserveMerges(observe("b"))
	now := time.Now()
	if err := a.st.Devices().Upsert(t.Context(), store.Device{ID: "pi", Name: "pi", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "b to observe the merged device", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Contains(told["b"], "pi")
	})
	mu.Lock()
	defer mu.Unlock()
	if len(told["a"]) != 0 {
		t.Fatalf("the writer observed its own write as merged: %v", told["a"])
	}
}
