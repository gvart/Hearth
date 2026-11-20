// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"fmt"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// Benchmarks of the reads an AP cluster scatters and gathers: the devices
// list and an audit page, on a 3-member AP cluster (N=2, members linked by
// in-process pipes, so without network latency) against a single hub's
// store. Run with: go test -run '^$' -bench 'AP' ./internal/cluster

const (
	benchDevices = 200
	benchAudit   = 2000
	benchPage    = 50
)

func benchStores(b *testing.B) map[string]*store.Store {
	b.Helper()
	ctx := b.Context()
	single := storetest.Open(b)
	an := newAPNet(b, 2, "a", "b", "c")
	ap := an.m("a").st
	for i := range benchDevices {
		for _, st := range []*store.Store{single, an.m([]string{"a", "b", "c"}[i%3]).st} {
			if err := st.Devices().Upsert(ctx, device(fmt.Sprintf("dev%04d", i), "n")); err != nil {
				b.Fatal(err)
			}
		}
	}
	for i := range benchAudit {
		e := store.AuditEntry{
			TS: time.Now(), ActorKind: "user", ActorID: "admin", Action: fmt.Sprintf("act%d", i%20),
			Decision: "allow", Result: "ok",
		}
		for _, st := range []*store.Store{single, an.m([]string{"a", "b", "c"}[i%3]).st} {
			if _, err := st.Audit().Append(ctx, e); err != nil {
				b.Fatal(err)
			}
		}
	}
	return map[string]*store.Store{"single": single, "ap3": ap}
}

func BenchmarkAPReads(b *testing.B) {
	stores := benchStores(b)
	for _, name := range []string{"single", "ap3"} {
		st := stores[name]
		b.Run("devices/"+name, func(b *testing.B) {
			for b.Loop() {
				l, err := st.Devices().List(b.Context())
				if err != nil || len(l) != benchDevices {
					b.Fatalf("list = %d, %v", len(l), err)
				}
			}
		})
		b.Run("audit-page/"+name, func(b *testing.B) {
			for b.Loop() {
				p, err := st.Audit().Query(b.Context(), store.AuditFilter{}, benchPage)
				if err != nil || len(p) != benchPage {
					b.Fatalf("page = %d, %v", len(p), err)
				}
			}
		})
	}
}
