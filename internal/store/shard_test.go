// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

func openTestWith(t *testing.T, opts ...Option) *Store {
	t.Helper()
	b, err := migratedDB()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hearth.db")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(t.Context(), path, opts...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Every command has a route in a sharded cluster, or is refused there on
// purpose.
func TestRouteOfEveryCommand(t *testing.T) {
	configCmds := []Command{PutConfigDocs{By: "x"}, DeleteConfigDoc{Kind: ConfigRunbook, Name: "r.yaml"}}
	for _, cmd := range configCmds {
		if r, err := RouteOf(cmd); err != nil || r.Kind != RouteGlobal || !r.Critical {
			t.Errorf("%s: route %+v, %v; want global and critical", cmd.Op(), r, err)
		}
	}
	for _, cmd := range append(allCommands(), configCmds...) {
		r, err := RouteOf(cmd)
		if err != nil {
			t.Errorf("%s: %v", cmd.Op(), err)
			continue
		}
		if r.Kind == RouteKey && r.Key == "" {
			t.Errorf("%s: keyed route without a key", cmd.Op())
		}
		if r.Kind == RouteSplit {
			if _, err := SplitCommand(cmd, func(k string) string { return k }); err != nil {
				t.Errorf("%s: %v", cmd.Op(), err)
			}
		}
	}
	// A sharded cluster re-seals one secret per command, a runbook run's on
	// its runbook's replicas.
	two := ResealSecrets{Secrets: []SealedSecret{{Table: SealedKubeClusters, ID: "a"}, {Table: SealedKubeClusters, ID: "b"}}}
	if _, err := RouteOf(two); !errors.Is(err, ErrNoRoute) {
		t.Errorf("reseal_secrets of two: err = %v, want ErrNoRoute", err)
	}
	run := ResealSecrets{Secrets: []SealedSecret{{Table: SealedRunbookRuns, ID: "r1", Key: "rb"}}}
	if r, err := RouteOf(run); err != nil || r.Kind != RouteKey || r.Key != "rb" || !r.Critical {
		t.Errorf("reseal_secrets of a run: %+v, %v; want critical on its runbook", r, err)
	}
}

// A command's route key is the partition key of every row it writes, so a
// replica of the key holds all the rows the command reads.
func TestRouteKeyIsRowPartition(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	for _, cmd := range allCommands() {
		r, err := RouteOf(cmd)
		if err != nil || r.Kind != RouteKey {
			continue
		}
		_, muts, err := s.ApplyLocalMutations(ctx, cmd)
		if err != nil {
			continue // a command the fixture order does not allow
		}
		for _, m := range muts {
			p, err := m.Placement()
			if err != nil {
				t.Fatalf("%s: %v", cmd.Op(), err)
			}
			if p.Global || p.Key != r.Key {
				t.Errorf("%s writes %s at %+v, routed to %q", cmd.Op(), m.Table, p, r.Key)
			}
		}
	}
}

// A command routed to a key, split by keys or run on every member writes
// sharded rows only, but for a password reset (#382): a storage member,
// which relays such a command, is no source of global rows.
func TestOnlyGlobalRoutesWriteGlobalRows(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	applied := map[RouteKind]int{}
	for _, cmd := range allCommands() {
		r, err := RouteOf(cmd)
		if err != nil || r.Kind == RouteGlobal {
			continue
		}
		if _, ok := cmd.(SetPasswordHash); ok {
			continue
		}
		_, muts, err := s.ApplyLocalMutations(ctx, cmd)
		if err != nil {
			continue // a command the fixture order does not allow
		}
		applied[r.Kind]++
		for _, m := range muts {
			if GlobalTable(m.Table) {
				t.Errorf("%s (route %v) writes the global table %s", cmd.Op(), r.Kind, m.Table)
			}
		}
	}
	for _, k := range []RouteKind{RouteKey, RouteSplit, RouteEvery} {
		if applied[k] == 0 {
			t.Errorf("no command of route %v applied: the test checks nothing of it", k)
		}
	}
}

func TestSplitAndMergeResults(t *testing.T) {
	cmd := MarkDevicesOffline{IDs: []string{"a", "b", "c"}, Cutoff: 7}
	parts, err := SplitCommand(cmd, func(k string) string {
		if k == "b" {
			return "m2"
		}
		return "m1"
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := parts["m1"].(MarkDevicesOffline); len(got.IDs) != 2 || got.IDs[0] != "a" || got.IDs[1] != "c" || got.Cutoff != 7 {
		t.Errorf("m1 = %+v", got)
	}
	if got := MergeResults(cmd, []Result{{Count: 2}, {Count: 1}}); got.Count != 3 {
		t.Errorf("split count = %d, want 3", got.Count)
	}
	every := MergeResults(MarkOffline{}, []Result{
		{Count: 2, Devices: []Device{{ID: "b"}, {ID: "a"}}}, {Count: 1, Devices: []Device{{ID: "a"}}},
	})
	if every.Count != 2 || len(every.Devices) != 2 || every.Devices[0].ID != "a" {
		t.Errorf("every = %+v", every)
	}
}

// Mutations keep their value types on the wire, for every table.
func TestMutationWireRoundTrip(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	var all []Mutation
	for _, cmd := range allCommands() {
		_, muts, err := s.ApplyLocalMutations(ctx, cmd)
		if err == nil {
			all = append(all, muts...)
		}
	}
	all = append(all, Mutation{Table: "devices", Row: map[string]any{"f": 1.5, "n": nil, "b": []byte{}, "i": int64(-7)}})
	tables := map[string]bool{}
	for _, m := range all {
		tables[m.Table] = true
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("%s: %v", m.Table, err)
		}
		var got Mutation
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%s: %v", m.Table, err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Errorf("%s: round trip\n got %#v\nwant %#v", m.Table, got, m)
		}
	}
	if len(tables) < 15 {
		t.Errorf("only %d tables covered", len(tables))
	}
	var bad Mutation
	if err := json.Unmarshal([]byte(`{"table":"devices","row":{"x":{"q":"1"}}}`), &bad); err == nil {
		t.Error("an unknown value tag was accepted")
	}
}

// The digests kept up to date write by write equal those built from the
// rows, through applies, merges and the tombstone GC.
func TestDigestIncremental(t *testing.T) {
	ctx := t.Context()
	a := openTestWith(t, WithDigest(), WithOrigin("a"))
	b := openTestWith(t, WithDigest(), WithOrigin("b"))
	var muts []Mutation
	for _, cmd := range allCommands() {
		_, ms, err := a.ApplyLocalMutations(ctx, withStamp(cmd, Stamp{HLC: a.clock.Now(), Origin: "a"}))
		if err == nil {
			muts = append(muts, ms...)
		}
	}
	if err := b.Merge(ctx, muts); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GCTombstones(ctx, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{a, b} {
		for _, sp := range []Space{SpaceShard, SpaceGlobal, SpaceMaster} {
			buckets := make([]int, sp.Buckets())
			for i := range buckets {
				buckets[i] = i
			}
			kept := s.BucketDigests(sp, buckets)
			if err := s.buildDigest(ctx); err != nil {
				t.Fatal(err)
			}
			if built := s.BucketDigests(sp, buckets); !slices.Equal(kept, built) {
				t.Errorf("%s space %d: kept digests differ from built ones", s.origin, sp)
			}
		}
	}
	// a dropped its tombstones, b has them: their digests differ (a
	// session's tombstone is a master row), and BucketRows finds the rows of
	// a differing bucket.
	buckets := make([]int, SpaceMaster.Buckets())
	for i := range buckets {
		buckets[i] = i
	}
	da, db := a.BucketDigests(SpaceMaster, buckets), b.BucketDigests(SpaceMaster, buckets)
	var diff []int
	for i := range da {
		if da[i] != db[i] {
			diff = append(diff, i)
		}
	}
	if len(diff) == 0 {
		t.Fatal("no bucket differs after a GC on one side")
	}
	rows, err := b.BucketRows(ctx, SpaceMaster, func(bk int) bool { return slices.Contains(diff, bk) })
	if err != nil || len(rows) == 0 {
		t.Fatalf("BucketRows = %v, %v", rows, err)
	}
	read, err := b.ReadRows(ctx, []RowRef{rows[0].RowRef})
	if err != nil || len(read) != 1 {
		t.Fatalf("ReadRows = %v, %v", read, err)
	}
}

// fakeShards serves the reads of a sharded store from member stores.
type fakeShards struct {
	self    string
	members map[string]*Store
	key     func(string) string // member holding a key
	// replicas, if set, are the members ReadReplicas reads; else the one
	// holding the key.
	replicas []string
	repairs  []RowRef
}

func (f *fakeShards) Holds(key string) bool { return f.key(key) == f.self }

func (f *fakeShards) ReadKey(ctx context.Context, key, q string, args Values) (Rows, error) {
	return f.members[f.key(key)].ReadLocal(ctx, q, args)
}

func (f *fakeShards) ReadReplicas(ctx context.Context, key, q string, args Values) ([]Rows, error) {
	if f.replicas != nil {
		var out []Rows
		for _, m := range f.replicas {
			r, err := f.members[m].ReadLocal(ctx, q, args)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}
	r, err := f.members[f.key(key)].ReadLocal(ctx, q, args)
	if err != nil {
		return nil, err
	}
	return []Rows{r}, nil
}

func (f *fakeShards) ReadAll(ctx context.Context, q string, args Values) ([]Rows, error) {
	var out []Rows
	ids := mapsKeys(f.members)
	slices.Sort(ids)
	for _, id := range ids {
		r, err := f.members[id].ReadLocal(ctx, q, args)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeShards) Repair(refs []RowRef) { f.repairs = append(f.repairs, refs...) }

func mapsKeys(m map[string]*Store) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Reads on a sharded store reach the members holding the rows: a point
// read on the replica, a list merged from all, a stale copy repaired.
func TestShardedReads(t *testing.T) {
	ctx := t.Context()
	sh := &fakeShards{
		self: "a", members: map[string]*Store{},
		key: func(k string) string {
			if k == "far" {
				return "b"
			}
			return "a"
		},
	}
	a := openTestWith(t, WithShards(sh), WithOrigin("a"))
	b := openTestWith(t, WithDigest(), WithOrigin("b"))
	sh.members["a"], sh.members["b"] = a, b
	now := time.UnixMilli(1_700_000_000_000)
	put := func(s *Store, id, name string) {
		t.Helper()
		if _, err := s.ApplyLocal(ctx, withStamp(UpsertDevice{
			ID: id, Name: name, Facts: "{}", Labels: "{}",
			FirstSeen: toMillis(now), LastSeen: toMillis(now), Status: StatusOnline,
		}, Stamp{HLC: a.clock.Now(), Origin: s.origin})); err != nil {
			t.Fatal(err)
		}
	}
	put(a, "near", "near")
	put(b, "far", "far")
	// Both hold "both"; b's copy is newer.
	put(a, "both", "old")
	put(b, "both", "new")

	d, err := a.Devices().Get(ctx, "far")
	if err != nil || d.Name != "far" {
		t.Fatalf("Get(far) = %+v, %v", d, err)
	}
	list, err := a.Devices().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range list {
		names = append(names, d.ID+"="+d.Name)
	}
	if want := []string{"both=new", "far=far", "near=near"}; !slices.Equal(names, want) {
		t.Errorf("List = %v, want %v", names, want)
	}
	if len(sh.repairs) != 1 || sh.repairs[0].Table != "devices" || sh.repairs[0].Key[0] != "both" {
		t.Errorf("repairs = %+v", sh.repairs)
	}
	// ReadLocal refuses writes.
	if _, err := b.ReadLocal(ctx, `DELETE FROM devices`, nil); err == nil {
		t.Error("ReadLocal ran a write")
	}
}

// The audit log pages across members newest first with an HLC cursor, each
// action's outcome folded in.
func TestShardedAuditPaging(t *testing.T) {
	ctx := t.Context()
	sh := &fakeShards{self: "a", members: map[string]*Store{}, key: func(string) string { return "a" }}
	a := openTestWith(t, WithShards(sh), WithOrigin("a"))
	b := openTestWith(t, WithDigest(), WithOrigin("b"))
	sh.members["a"], sh.members["b"] = a, b
	var want []string
	for i := range 6 {
		s := a
		if i%2 == 1 {
			s = b
		}
		action := "act" + string(rune('0'+i))
		detail := `{"audit_op":"op` + action + `"}`
		if _, err := s.ApplyLocal(ctx, withStamp(AppendAudit{
			TS: int64(i), ActorKind: "user", ActorID: "u", Action: action,
			Decision: "allow", Result: "pending", Detail: detail,
		}, Stamp{HLC: a.clock.Now(), Origin: s.origin})); err != nil {
			t.Fatal(err)
		}
		// The outcome lands on the same member.
		if _, err := s.ApplyLocal(ctx, withStamp(AppendAudit{
			TS: int64(i), ActorKind: "user", ActorID: "u", Action: action,
			Decision: "allow", Result: "ok", Detail: `{"audit_outcome_of":"op` + action + `"}`,
		},
			Stamp{HLC: a.clock.Now(), Origin: s.origin})); err != nil {
			t.Fatal(err)
		}
		want = append([]string{action}, want...)
	}
	var got []string
	var cursor string
	for {
		page, err := a.Audit().Query(ctx, AuditFilter{BeforeCursor: cursor}, 4)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if e.Result != "ok" {
				t.Errorf("%s: result %q, want the outcome's", e.Action, e.Result)
			}
			if string(e.Detail) != "{}" {
				t.Errorf("%s: detail %s keeps the op keys", e.Action, e.Detail)
			}
			got = append(got, e.Action)
		}
		cursor = page[len(page)-1].Cursor
	}
	if !slices.Equal(got, want) {
		t.Errorf("pages = %v, want %v", got, want)
	}
}

// Entries of two members with the same HLC page in the strict order of the
// global id: across every page boundary, each appears exactly once.
func TestShardedAuditPagingHLCTies(t *testing.T) {
	ctx := t.Context()
	sh := &fakeShards{self: "a", members: map[string]*Store{}, key: func(string) string { return "a" }}
	a := openTestWith(t, WithShards(sh), WithOrigin("a"))
	b := openTestWith(t, WithDigest(), WithOrigin("b"))
	sh.members["a"], sh.members["b"] = a, b
	tie := a.clock.Now()
	want := map[string]bool{}
	for i := range 5 {
		for _, s := range []*Store{a, b} {
			action := fmt.Sprintf("%s-%d", s.origin, i)
			if _, err := s.ApplyLocal(ctx, withStamp(AppendAudit{
				TS: 1, ActorKind: "user", ActorID: "u", Action: action, Decision: "allow", Result: "ok", Detail: `{}`,
			}, Stamp{HLC: tie, Origin: s.origin})); err != nil {
				t.Fatal(err)
			}
			want[action] = true
		}
	}
	for _, size := range []int{1, 2, 3, 4, 7} {
		seen := map[string]int{}
		cursor, pages := "", 0
		for ; pages < 20; pages++ {
			page, err := a.Audit().Query(ctx, AuditFilter{BeforeCursor: cursor}, size)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) == 0 {
				break
			}
			for _, e := range page {
				seen[e.Action]++
			}
			cursor = page[len(page)-1].Cursor
		}
		if len(seen) != len(want) {
			t.Errorf("page size %d: %d of %d entries seen: %v", size, len(seen), len(want), seen)
		}
		for action, n := range seen {
			if n != 1 || !want[action] {
				t.Errorf("page size %d: %s seen %d times", size, action, n)
			}
		}
	}
	for _, bad := range []string{"x", "1.2", "0.0.a", "1.-1.a", "1.2."} {
		if err := CheckAuditCursor(bad); !errors.Is(err, ErrBadCursor) {
			t.Errorf("cursor %q: err = %v, want ErrBadCursor", bad, err)
		}
		if _, err := a.Audit().Query(ctx, AuditFilter{BeforeCursor: bad}, 5); !errors.Is(err, ErrBadCursor) {
			t.Errorf("query with cursor %q: err = %v", bad, err)
		}
	}
}
