// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"reflect"
	"testing"
	"time"
)

// TestObserveMerges: a Merge tells the observer the rows it took, by table
// and key, and nothing for rows it already holds at that version or newer,
// nor for audit entries.
func TestObserveMerges(t *testing.T) {
	ctx := t.Context()
	start := time.Unix(1_700_000_000, 0)
	a := openMember(t, "a", start)
	b := openMember(t, "b", start)
	dev := write(t, a, UpsertDevice{ID: "d1", Name: "one", Facts: "{}", Labels: "{}", FirstSeen: 1, LastSeen: 1, Status: StatusOnline})
	audit := write(t, a, AppendAudit{TS: 1, ActorKind: "web", ActorID: "a", Action: "x", Decision: "allow", Detail: "{}"})

	var told [][]MergedRow
	b.ObserveMerges(func(rows []MergedRow) { told = append(told, rows) })
	tests := []struct {
		name string
		muts []Mutation
		want [][]MergedRow
	}{
		{"a new device row", dev, [][]MergedRow{{{Table: "devices", Key: []any{"d1"}}}}},
		{"the same row again", dev, nil},
		{"an audit entry", audit, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			told = nil
			if err := b.Merge(ctx, tt.muts); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(told, tt.want) {
				t.Fatalf("told %v, want %v", told, tt.want)
			}
		})
	}
	b.ObserveMerges(nil)
	told = nil
	newer := write(t, a, MarkSeen{ID: "d1", Now: 5})
	if err := b.Merge(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if told != nil {
		t.Fatalf("told %v after ObserveMerges(nil)", told)
	}
}
