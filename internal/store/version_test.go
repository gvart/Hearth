// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hlc"
)

// stepClock is a wall clock that moves 1 ms each time it is read, from
// start.
type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

// openMember opens a store stamping writes as origin, on a wall clock that
// starts at start.
func openMember(t *testing.T, origin string, start time.Time) *Store {
	t.Helper()
	c := &stepClock{t: start}
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"),
		WithOrigin(origin), WithClock(hlc.NewClock(c.now)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// openAtSchema opens a new store migrated down to schema v, as a cluster
// member whose database is not migrated yet.
func openAtSchema(t *testing.T, v int64) *Store {
	t.Helper()
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
	if _, err := p.DownTo(ctx, v); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// write applies cmd through s's repositories' path (stamped, as a hub does)
// and returns the mutations it merged.
func write(t *testing.T, s *Store, cmd Command) []Mutation {
	t.Helper()
	muts, err := tryWrite(t.Context(), s, cmd)
	if err != nil {
		t.Fatalf("%s: %v", cmd.Op(), err)
	}
	return muts
}

func tryWrite(ctx context.Context, s *Store, cmd Command) ([]Mutation, error) {
	cmd = withStamp(cmd, Stamp{HLC: s.clock.Now(), Origin: s.origin})
	_, muts, err := s.ApplyLocalMutations(ctx, cmd)
	return muts, err
}

// dumpVersioned returns every replicated row of db, by table, in key order,
// version columns included, and the audit log in the order of its global
// id, without the local id: what must be identical on every member that
// merged the same mutations.
func dumpVersioned(t *testing.T, db *sql.DB) map[string][]string {
	t.Helper()
	ctx := t.Context()
	out := map[string][]string{}
	queries := map[string]string{
		auditTable: `SELECT ts, actor_kind, actor_id, action, target, decision, result, detail, audit_op,
			audit_outcome_of, audit_key, _hlc, _origin, _seq FROM audit_log ORDER BY _hlc, _origin, _seq`,
	}
	for table, spec := range tables {
		queries[table] = `SELECT * FROM ` + table + ` ORDER BY ` + strings.Join(spec.pk, ", ")
	}
	for table, q := range queries {
		rows, err := db.QueryContext(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := scanRows(rows)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			var b strings.Builder
			for _, c := range slices.Sorted(maps.Keys(r)) {
				fmt.Fprintf(&b, "%s=%#v ", c, r[c])
			}
			out[table] = append(out[table], b.String())
		}
	}
	return out
}

func TestEveryTableIsVersioned(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	want := append(slices.Collect(maps.Keys(tables)), auditTable)
	slices.Sort(want)
	if got := tableNames(ctx, t, s.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("tables = %v, the spec has %v: a new table needs a merge spec", got, want)
	}
	for _, table := range want {
		rows, err := s.db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		_ = rows.Close()
		need := []string{colHLC, colOrigin, colDeleted}
		if table == auditTable {
			need = []string{colHLC, colOrigin, colSeq}
		}
		for _, c := range need {
			if !slices.Contains(cols, c) {
				t.Errorf("%s has no %s column", table, c)
			}
		}
	}
}

// TestMergeConverges is the property test of the versioned store: three
// members write concurrently, conflicting on the same rows (devices,
// revocations, deletes and re-adds, audit entries), and every member that
// merges the resulting mutations, in any order, in any batches, with
// duplicates, ends with the same rows.
func TestMergeConverges(t *testing.T) {
	for seed := range int64(8) {
		t.Run(fmt.Sprint("seed ", seed), func(t *testing.T) { testMergeConverges(t, seed) })
	}
}

func testMergeConverges(t *testing.T, seed int64) {
	ctx := t.Context()
	rng := newRand(seed)
	base := time.Now().Add(-time.Hour)
	members := []*Store{
		openMember(t, "a", base),
		openMember(t, "b", base.Add(-2*time.Second)), // a clock behind
		openMember(t, "c", base.Add(1500*time.Millisecond)),
	}

	// A common start: the parents every member's writes refer to.
	seedMuts := slices.Concat(
		write(t, members[0], UpsertDevice{ID: "d1", Name: "one", Facts: "{}", Labels: "{}", FirstSeen: 1, LastSeen: 1, Status: StatusOnline}),
		write(t, members[0], UpsertDevice{ID: "d2", Name: "two", Facts: "{}", Labels: "{}", FirstSeen: 1, LastSeen: 1, Status: StatusOffline}),
		write(t, members[0], CreateCert{Serial: "c1", DeviceID: "d1", Fingerprint: "f1"}),
		write(t, members[0], CreateCert{Serial: "c2", DeviceID: "d2"}),
		write(t, members[0], CreatePanel{ID: "p1", Name: "hall", Widgets: "[]", At: 1}),
		write(t, members[0], CreatePanelLink{ID: "l1", PanelID: "p1", Hash: []byte{1}, CreatedAt: 1}),
		write(t, members[0], AddKubeCluster{ID: KubeClusterID("lab"), Name: "lab", Sealed: []byte{1}, CreatedAt: 1}),
		write(t, members[0], CreateMCPToken{Name: "claude", Hash: []byte{2}, Scope: "read", CreatedAt: 1}),
	)
	for _, m := range members[1:] {
		if err := m.Merge(ctx, seedMuts); err != nil {
			t.Fatal(err)
		}
	}

	// Concurrent writes. A write may fail (a token used, a row gone): its
	// outcome is part of what is merged, or not.
	muts := slices.Clone(seedMuts)
	for i := range 120 {
		m := members[rng.intn(len(members))]
		dev := []string{"d1", "d2"}[rng.intn(2)]
		var cmd Command
		switch rng.intn(14) {
		case 0:
			cmd = UpsertDevice{ID: dev, Name: fmt.Sprint("name", i), Facts: "{}", Labels: "{}", FirstSeen: 2, LastSeen: int64(i), Status: StatusOnline}
		case 1:
			cmd = MarkSeen{ID: dev, Now: int64(100 + i)}
		case 2:
			cmd = MarkDevicesOffline{IDs: []string{dev}}
		case 3:
			cmd = RevokeDevice{DeviceID: dev, Now: int64(1000 + i)}
		case 4:
			cmd = PinCert{Serial: "c2", DeviceID: "d2", Fingerprint: fmt.Sprint("fp", i), Now: int64(i)}
		case 5:
			cmd = UpdatePanel{ID: "p1", Name: fmt.Sprint("hall", i), Widgets: "[]", At: int64(i)}
		case 6:
			cmd = DeletePanel{ID: "p1"}
		case 7:
			cmd = CreatePanel{ID: "p1", Name: "again", Widgets: "[]", At: int64(i)}
		case 8:
			cmd = RevokePanelLink{PanelID: "p1", ID: "l1", At: int64(2000 + i)}
		case 9:
			cmd = RemoveKubeCluster{ID: KubeClusterID("lab")}
		case 10:
			cmd = AddKubeCluster{ID: KubeClusterID("lab"), Name: "lab", Sealed: []byte{byte(i)}, CreatedAt: int64(i)}
		case 11:
			cmd = RevokeMCPToken{Name: "claude", At: int64(3000 + i)}
		case 12:
			cmd = AppendAudit{TS: int64(i), ActorKind: "web", ActorID: m.origin, Action: "x", Decision: "allow", Detail: "{}"}
		default:
			cmd = RecordNetworkScan{At: int64(i), Hosts: []ScannedHost{{MAC: "aa:bb:cc:dd:ee:ff", IP: fmt.Sprint("10.0.0.", i%3)}}}
		}
		out, err := tryWrite(ctx, m, cmd)
		if err != nil && !IsDomainError(err) {
			t.Fatalf("write %d %s: %v", i, cmd.Op(), err)
		}
		muts = append(muts, out...)
	}

	// Each replica merges every mutation in an order of its own, in random
	// batches, some twice. Parents first: certs and share links refer to
	// devices and panels with a foreign key the merge keeps.
	var want map[string][]string
	for r := range 5 {
		replica := openTest(t)
		order := slices.Clone(muts)
		rng.shuffle(order)
		for range len(order) / 4 {
			order = append(order, order[rng.intn(len(order))])
		}
		slices.SortStableFunc(order, func(a, b Mutation) int { return parentRank(a) - parentRank(b) })
		for len(order) > 0 {
			n := min(len(order), 1+rng.intn(10))
			if err := replica.Merge(ctx, order[:n]); err != nil {
				t.Fatalf("replica %d: %v", r, err)
			}
			order = order[n:]
		}
		got := dumpVersioned(t, replica.db)
		if want == nil {
			want = got
			continue
		}
		if !reflect.DeepEqual(got, want) {
			for table := range want {
				if !reflect.DeepEqual(got[table], want[table]) {
					t.Errorf("replica %d, %s:\n got %v\nwant %v", r, table, got[table], want[table])
				}
			}
			t.FailNow()
		}
		if r == 0 {
			checkConvergedReads(t, replica)
		}
	}
	for _, table := range []string{"devices", "certs", "panels", "panel_links", "kube_clusters", "mcp_tokens", "network_hosts", auditTable} {
		if len(want[table]) == 0 {
			t.Errorf("%s is empty: the comparison proves nothing", table)
		}
	}
}

// parentRank orders the mutations of parent tables first.
func parentRank(m Mutation) int {
	if m.Table == "devices" || m.Table == "panels" {
		return 0
	}
	return 1
}

// checkConvergedReads checks the reads of a converged replica see what the
// writes did: deny wins, and tombstones are not read.
func checkConvergedReads(t *testing.T, s *Store) {
	t.Helper()
	ctx := t.Context()
	if _, err := s.Devices().List(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Panels().List(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Audit().List(ctx, 1000); err != nil {
		t.Fatal(err)
	}
}

// rnd is a small deterministic generator (the test must not depend on
// math/rand's sequence across Go releases).
type rnd struct{ x uint64 }

func newRand(seed int64) *rnd { return &rnd{x: uint64(seed)*0x9e3779b97f4a7c15 + 1} } //nolint:gosec // a test seed

func (r *rnd) next() uint64 {
	r.x ^= r.x << 13
	r.x ^= r.x >> 7
	r.x ^= r.x << 17
	return r.x
}

func (r *rnd) intn(n int) int { return int(r.next() % uint64(n)) } //nolint:gosec // n is small and positive

func (r *rnd) shuffle(m []Mutation) {
	for i := len(m) - 1; i > 0; i-- {
		j := r.intn(i + 1)
		m[i], m[j] = m[j], m[i]
	}
}

// deviceMut is a devices row mutation.
func deviceMut(id, name string, h hlc.Timestamp, origin string) Mutation {
	return Mutation{Table: "devices", HLC: h, Origin: origin, Row: map[string]any{
		"id": id, "name": name, "hostname": "", "os": "", "arch": "", "facts": "{}", "labels": "{}",
		"first_seen": int64(1), "last_seen": int64(1), "status": StatusOnline, "boot_time": nil,
	}}
}

func TestMergeLastWriterWins(t *testing.T) {
	now := hlc.New(time.Now())
	tests := []struct {
		name string
		muts []Mutation
		want string
	}{
		{"newer wins", []Mutation{deviceMut("pi", "old", now, "a"), deviceMut("pi", "new", now+1, "a")}, "new"},
		{"older loses", []Mutation{deviceMut("pi", "new", now+1, "a"), deviceMut("pi", "old", now, "a")}, "new"},
		{"origin breaks a tie", []Mutation{deviceMut("pi", "b", now, "b"), deviceMut("pi", "a", now, "a")}, "b"},
		{"same version again", []Mutation{deviceMut("pi", "x", now, "a"), deviceMut("pi", "x", now, "a")}, "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTest(t)
			if err := s.Merge(t.Context(), tt.muts); err != nil {
				t.Fatal(err)
			}
			d, err := s.Devices().Get(t.Context(), "pi")
			if err != nil || d.Name != tt.want {
				t.Fatalf("Get = %+v, %v; want name %q", d, err, tt.want)
			}
		})
	}
}

// TestRevocationIsNeverCleared: a revocation, once a replica has it, stays,
// whatever newer or older version of the row arrives, and whatever a later
// command writes.
func TestRevocationIsNeverCleared(t *testing.T) {
	ctx := t.Context()
	now := hlc.New(time.Now())
	type setOnce struct {
		table, col string
		row        map[string]any
	}
	cases := []setOnce{
		{"certs", "revoked_at", map[string]any{"serial": "0a", "device_id": "pi", "fingerprint": nil, "ca_fp": nil, "pin_mismatch_at": nil}},
		{"certs", "pin_mismatch_at", map[string]any{"serial": "0a", "device_id": "pi", "fingerprint": nil, "ca_fp": nil, "revoked_at": nil}},
		{"hub_certs", "revoked_at", map[string]any{"serial": "0b", "node_id": "hub-a", "fingerprint": nil, "ca_fp": nil}},
		{"mcp_tokens", "revoked_at", map[string]any{"name": "claude", "hash": []byte{1}, "scope": "read", "created_at": int64(1)}},
		{"dashboard_tokens", "revoked_at", map[string]any{"id": "d", "name": "home", "hash": []byte{2}, "created_at": int64(1), "expires_at": nil}},
		{"panel_links", "revoked_at", map[string]any{"id": "l", "panel_id": "p", "hash": []byte{3}, "created_at": int64(1), "expires_at": nil}},
		{"tokens", "used_at", map[string]any{"hash": []byte{4}, "labels": "{}", "expires_at": int64(9)}},
	}
	with := func(r map[string]any, col string, v any) map[string]any {
		out := maps.Clone(r)
		out[col] = v
		return out
	}
	for _, c := range cases {
		t.Run(c.table+"."+c.col, func(t *testing.T) {
			s := openTest(t)
			parents := []Mutation{
				deviceMut("pi", "pi", now, "a"),
				{Table: "panels", HLC: now, Origin: "a", Row: map[string]any{"id": "p", "name": "p", "widgets": "[]", "created_at": int64(1), "updated_at": int64(1)}},
			}
			if err := s.Merge(ctx, parents); err != nil {
				t.Fatal(err)
			}
			revoked := Mutation{Table: c.table, HLC: now + 10, Origin: "a", Row: with(c.row, c.col, int64(500))}
			newer := Mutation{Table: c.table, HLC: now + 20, Origin: "b", Row: with(c.row, c.col, nil)}
			earlier := Mutation{Table: c.table, HLC: now + 5, Origin: "c", Row: with(c.row, c.col, int64(400))}
			for _, order := range [][]Mutation{{revoked, newer}, {newer, revoked}, {newer, revoked, earlier}, {earlier, newer, revoked}} {
				if _, err := s.db.ExecContext(ctx, `DELETE FROM `+c.table); err != nil { //nolint:gosec // a table of the test
					t.Fatal(err)
				}
				if err := s.Merge(ctx, order); err != nil {
					t.Fatal(err)
				}
				want := int64(500)
				if slices.ContainsFunc(order, func(m Mutation) bool { return m.Origin == "c" }) {
					want = 400 // the earliest revocation any version had
				}
				var got sql.NullInt64
				if err := s.db.QueryRowContext(ctx, `SELECT `+c.col+` FROM `+c.table).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if !got.Valid || got.Int64 != want {
					t.Fatalf("after %d mutations: %s = %v, want %d", len(order), c.col, got, want)
				}
			}
		})
	}

	// A command applied after the revocation keeps it too.
	s := openTest(t)
	if err := s.Devices().Upsert(ctx, Device{ID: "pi"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Certs().Create(ctx, "0a", "pi"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Certs().RevokeDevice(ctx, "pi", time.Now()); err != nil {
		t.Fatal(err)
	}
	unrevoke := Mutation{Table: "certs", HLC: s.clock.Now() + 1000, Origin: "zz", Row: map[string]any{
		"serial": "0a", "device_id": "pi", "revoked_at": nil, "fingerprint": nil, "ca_fp": nil, "pin_mismatch_at": nil,
	}}
	if err := s.Merge(ctx, []Mutation{unrevoke}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Certs().Pin(ctx, "0a", "pi", "fp", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Certs().Check(ctx, "0a", "pi"); !errors.Is(err, ErrCertRevoked) {
		t.Fatalf("Check after a newer write without the revocation = %v, want ErrCertRevoked", err)
	}
}

// TestAuditIsNeverOverwritten: an audit entry merged again, with other
// content or as a tombstone, is not changed, and the log refuses an update
// or delete outright.
func TestAuditIsNeverOverwritten(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	if _, err := s.Audit().Append(ctx, AuditEntry{ActorKind: "web", ActorID: "a", Action: "x", Decision: "allow", Key: "k"}); err != nil {
		t.Fatal(err)
	}
	before := dumpVersioned(t, s.db)[auditTable]
	entry := mutationsOf(t, s.db)[0]

	forged := entry
	forged.Row = maps.Clone(entry.Row)
	forged.Row["decision"], forged.Row["audit_key"] = "deny", nil
	if err := s.Merge(ctx, []Mutation{forged}); err != nil {
		t.Fatal(err)
	}
	sameKey := entry
	sameKey.HLC++
	sameKey.Row = maps.Clone(entry.Row)
	sameKey.Row["decision"] = "deny"
	if err := s.Merge(ctx, []Mutation{sameKey}); err != nil {
		t.Fatal(err)
	}
	if got := dumpVersioned(t, s.db)[auditTable]; !reflect.DeepEqual(got, before) {
		t.Fatalf("audit log changed by a merge:\n got %v\nwant %v", got, before)
	}

	tomb := entry
	tomb.Deleted = true
	if err := s.Merge(ctx, []Mutation{tomb}); err == nil {
		t.Fatal("Merge accepted an audit tombstone")
	}
	for _, q := range []string{`UPDATE audit_log SET decision = 'deny'`, `DELETE FROM audit_log`, `UPDATE audit_log SET _hlc = 0`} {
		if _, err := s.db.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want the append-only guard", q, err)
		}
	}
	if got := dumpVersioned(t, s.db)[auditTable]; !reflect.DeepEqual(got, before) {
		t.Fatalf("audit log changed:\n got %v\nwant %v", got, before)
	}
}

// mutationsOf reads the audit log of db back as the mutations that made it.
func mutationsOf(t *testing.T, db *sql.DB) []Mutation {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT ts, actor_kind, actor_id, action, target, decision, result, detail,
		audit_key, _hlc, _origin, _seq FROM audit_log ORDER BY _hlc`)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := scanRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	var out []Mutation
	for _, r := range rs {
		h, origin := r.version()
		m := Mutation{Table: auditTable, HLC: h, Origin: origin, Seq: r.int(colSeq), Row: r.data()}
		delete(m.Row, colSeq)
		out = append(out, m)
	}
	return out
}

func TestMergeRejectsFutureSkew(t *testing.T) {
	ctx := t.Context()
	wall := time.Now()
	tests := []struct {
		name    string
		ahead   time.Duration
		wantErr bool
	}{
		{"in the past", -time.Hour, false},
		{"within the bound", hlc.MaxSkew - time.Second, false},
		{"past the bound", hlc.MaxSkew + time.Second, true},
		{"a year ahead", 365 * 24 * time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Open(ctx, filepath.Join(t.TempDir(), "hearth.db"), WithClock(hlc.NewClock(func() time.Time { return wall })))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ok := deviceMut("ok", "ok", hlc.New(wall), "a")
			skewed := deviceMut("pi", "pi", hlc.New(wall.Add(tt.ahead)), "b")
			err = s.Merge(ctx, []Mutation{ok, skewed})
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Merge = %v", err)
				}
				return
			}
			if !errors.Is(err, hlc.ErrSkew) {
				t.Fatalf("Merge = %v, want hlc.ErrSkew", err)
			}
			if devs, err := s.Devices().List(ctx); err != nil || len(devs) != 0 {
				t.Fatalf("a refused batch wrote %v (%v)", devs, err)
			}
			if s.clock.Last() >= skewed.HLC {
				t.Fatalf("the clock moved to the refused timestamp %s", s.clock.Last())
			}
		})
	}
}

// TestTombstoneIsNotResurrected: a deleted row stays deleted against an
// older write, merged before or after the tombstone, and comes back only by
// a newer one.
func TestTombstoneIsNotResurrected(t *testing.T) {
	ctx := t.Context()
	src := openMember(t, "a", time.Now().Add(-time.Minute))
	created := write(t, src, CreatePanel{ID: "p1", Name: "hall", Widgets: "[]", At: 1})
	updated := write(t, src, UpdatePanel{ID: "p1", Name: "hallway", Widgets: "[]", At: 2})
	deleted := write(t, src, DeletePanel{ID: "p1"})
	if len(deleted) != 1 || !deleted[0].Deleted {
		t.Fatalf("DeletePanel merged %+v, want one tombstone", deleted)
	}
	for _, order := range [][]Mutation{
		slices.Concat(created, updated, deleted),
		slices.Concat(deleted, updated, created),
		slices.Concat(updated, deleted, created),
	} {
		s := openTest(t)
		for _, m := range order {
			if err := s.Merge(ctx, []Mutation{m}); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := s.Panels().List(ctx); err != nil || len(got) != 0 {
			t.Fatalf("List = %+v, %v; want the panel deleted", got, err)
		}
		if _, err := s.Panels().Get(ctx, "p1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get = %v, want ErrNotFound", err)
		}
	}

	// A newer write brings it back, on the member and on a replica.
	again := write(t, src, CreatePanel{ID: "p1", Name: "again", Widgets: "[]", At: 3})
	s := openTest(t)
	if err := s.Merge(ctx, slices.Concat(again, deleted, created)); err != nil {
		t.Fatal(err)
	}
	for _, st := range []*Store{src, s} {
		if p, err := st.Panels().Get(ctx, "p1"); err != nil || p.Name != "again" {
			t.Fatalf("Get after the re-create = %+v, %v", p, err)
		}
	}
}

// TestApplyFollowsLogOrder: in a replicated log a command stamped by a hub
// whose clock is behind still supersedes the row it read, as it did before
// versions: the command already reported success to its caller.
func TestApplyFollowsLogOrder(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	ahead := Stamp{HLC: hlc.New(time.Now().Add(time.Hour)), Origin: "fast"}
	behind := Stamp{HLC: hlc.New(time.Now().Add(-time.Hour)), Origin: "slow"}
	if _, err := s.ApplyLocal(ctx, withStamp(UpsertDevice{ID: "pi", Status: StatusOnline, Facts: "{}", Labels: "{}"}, ahead)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyLocal(ctx, withStamp(MarkDevicesOffline{IDs: []string{"pi"}}, behind)); err != nil {
		t.Fatal(err)
	}
	d, err := s.Devices().Get(ctx, "pi")
	if err != nil || d.Status != StatusOffline {
		t.Fatalf("Get = %+v, %v; want the later command's offline", d, err)
	}
	var h int64
	var origin string
	if err := s.db.QueryRowContext(ctx, `SELECT _hlc, _origin FROM devices`).Scan(&h, &origin); err != nil {
		t.Fatal(err)
	}
	if hlc.Timestamp(h) != ahead.HLC+1 || origin != "slow" { //nolint:gosec // a test HLC
		t.Fatalf("version = %d/%s, want %d/slow: one past the row it superseded", h, origin, ahead.HLC+1)
	}
	// And this hub's next stamp is newer still.
	if now := s.clock.Now(); now <= ahead.HLC+1 {
		t.Fatalf("clock = %s after applying %s", now, ahead.HLC+1)
	}
}

// TestUnstampedCommandIsDeterministic: a command without a stamp (from a
// log written before versions) gets the same version on every member.
func TestUnstampedCommandIsDeterministic(t *testing.T) {
	ctx := t.Context()
	cmds := []Command{
		UpsertDevice{ID: "pi", Facts: "{}", Labels: "{}"},
		MarkSeen{ID: "pi", Now: 5},
		AppendAudit{TS: 1, ActorKind: "web", ActorID: "a", Action: "x", Decision: "allow", Detail: "{}"},
		CreatePanel{ID: "p", Name: "p", Widgets: "[]"},
		DeletePanel{ID: "p"},
		AppendAudit{TS: 1, ActorKind: "web", ActorID: "a", Action: "y", Decision: "allow", Detail: "{}"},
	}
	var dumps []map[string][]string
	for range 2 {
		s := openTest(t) // each with a clock and origin of its own
		for _, c := range cmds {
			if _, err := s.ApplyLocal(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		dumps = append(dumps, dumpVersioned(t, s.db))
	}
	if !reflect.DeepEqual(dumps[0], dumps[1]) {
		t.Fatalf("members differ:\n%v\n%v", dumps[0], dumps[1])
	}
	if got := dumps[0]["devices"][0]; !strings.Contains(got, `_hlc=2 `) || !strings.Contains(got, `_origin=""`) {
		t.Fatalf("devices row %s: want version 2, no origin", got)
	}
}

// TestStampsOnlyFromVersionedSchema: a member not migrated yet sends
// commands without a stamp, which a hub on an older binary could not decode.
func TestStampsOnlyFromVersionedSchema(t *testing.T) {
	ctx := t.Context()
	for _, tt := range []struct {
		schema    int64
		wantStamp bool
	}{{VersionedSchema - 1, false}, {VersionedSchema, true}} {
		s := openAtSchema(t, tt.schema)
		var sent []Command
		s.applier = ApplierFunc(func(ctx context.Context, cmd Command) (Result, error) {
			sent = append(sent, cmd)
			return s.ApplyLocal(ctx, cmd)
		})
		if err := s.Devices().Upsert(ctx, Device{ID: "pi"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Devices().MarkSeen(ctx, "pi", time.Now()); err != nil {
			t.Fatal(err)
		}
		for _, cmd := range sent {
			if got := stampOf(cmd) != (Stamp{}); got != tt.wantStamp {
				t.Errorf("schema %d: %s stamped = %v, want %v", tt.schema, cmd.Op(), got, tt.wantStamp)
			}
			b, err := EncodeCommand(cmd)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(b), `"_hlc"`); got != tt.wantStamp {
				t.Errorf("schema %d: encoded %s carries a stamp = %v, want %v", tt.schema, b, got, tt.wantStamp)
			}
		}
		if d, err := s.Devices().Get(ctx, "pi"); err != nil || d.Status != StatusOnline {
			t.Errorf("schema %d: Get = %+v, %v", tt.schema, d, err)
		}
	}
}

// TestDecodeUnstampedCommand: a command encoded before stamps decodes with
// the zero stamp.
func TestDecodeUnstampedCommand(t *testing.T) {
	cmd, err := DecodeCommand([]byte(`{"v":1,"op":"mark_seen","cmd":{"id":"pi","now":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := stampOf(cmd); got != (Stamp{}) {
		t.Fatalf("stamp = %+v, want none", got)
	}
	st := Stamp{HLC: 42, Origin: "a"}
	b, err := EncodeCommand(withStamp(cmd, st))
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeCommand(b)
	if err != nil || stampOf(back) != st {
		t.Fatalf("round trip of %s = %+v, %v", b, back, err)
	}
}

func TestGCTombstones(t *testing.T) {
	ctx := t.Context()
	src := openMember(t, "a", time.Now().Add(-10*24*time.Hour))
	muts := slices.Concat(
		write(t, src, CreatePanel{ID: "old", Name: "old", Widgets: "[]"}),
		write(t, src, DeletePanel{ID: "old"}),
		write(t, src, CreatePanel{ID: "live", Name: "live", Widgets: "[]"}),
	)
	recent := hlc.New(time.Now().Add(-time.Hour))
	muts = append(muts, Mutation{Table: "panels", HLC: recent, Origin: "b", Deleted: true, Row: map[string]any{
		"id": "new", "name": "new", "widgets": "[]", "created_at": int64(1), "updated_at": int64(1),
	}})
	s := openTest(t)
	if err := s.Merge(ctx, muts); err != nil {
		t.Fatal(err)
	}
	count := func() (n int) {
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM panels WHERE _deleted = 1`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() != 2 {
		t.Fatalf("%d tombstones before GC, want 2", count())
	}
	n, err := s.GCTombstones(ctx, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("GCTombstones = %d, %v; want the one older than %s", n, err, TombstoneTTL)
	}
	if count() != 1 {
		t.Fatalf("%d tombstones after GC, want the recent one", count())
	}
	if p, err := s.Panels().List(ctx); err != nil || len(p) != 1 || p[0].ID != "live" {
		t.Fatalf("List after GC = %+v, %v", p, err)
	}
	// Below VersionedSchema there is nothing to collect.
	old := openAtSchema(t, VersionedSchema-1)
	if n, err := old.GCTombstones(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("GCTombstones before the schema = %d, %v", n, err)
	}
}

// TestOpenObservesStoredVersions: a hub whose wall clock went back (a Pi
// without an RTC) still stamps writes that supersede what it wrote before.
func TestOpenObservesStoredVersions(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	later := time.Now().Add(24 * time.Hour)
	s, err := Open(ctx, path, WithClock(hlc.NewClock(func() time.Time { return later })))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Devices().Upsert(ctx, Device{ID: "pi", Name: "first"}); err != nil {
		t.Fatal(err)
	}
	stored := s.clock.Last()
	_ = s.Close()
	earlier := time.Unix(0, 0)
	s, err = Open(ctx, path, WithClock(hlc.NewClock(func() time.Time { return earlier })))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if now := s.clock.Now(); now <= stored {
		t.Fatalf("first stamp after reopening = %s, want past the stored %s", now, stored)
	}
}

// TestRemoveThenAddKeepsNoName: a deleted cluster's tombstone keeps neither
// its kubeconfig nor its name, so the name can be added again, also over a
// cluster stored before natural ids, on every member alike whether or not it
// still holds the tombstone.
func TestRemoveThenAddKeepsNoName(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, VersionedSchema-1)
	kc := s.KubeClusters()
	if err := kc.Add(ctx, KubeCluster{ID: "random01", Name: "lab", Sealed: []byte("secret"), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateTo(ctx, VersionedSchema); err != nil {
		t.Fatal(err)
	}
	if err := kc.Remove(ctx, "random01"); err != nil {
		t.Fatal(err)
	}
	var name string
	var cfg []byte
	if err := s.db.QueryRowContext(ctx, `SELECT name, kubeconfig FROM kube_clusters WHERE id = 'random01'`).Scan(&name, &cfg); err != nil {
		t.Fatal(err)
	}
	if name == "lab" || len(cfg) != 0 {
		t.Fatalf("tombstone keeps name %q and kubeconfig %q", name, cfg)
	}
	if err := kc.Add(ctx, KubeCluster{ID: KubeClusterID("lab"), Name: "lab", Sealed: []byte("x"), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("Add after Remove: %v", err)
	}
	if err := kc.Add(ctx, KubeCluster{ID: KubeClusterID("lab"), Name: "lab", Sealed: []byte("y"), CreatedAt: time.Now()}); !errors.Is(err, ErrExists) || !IsDomainError(err) {
		t.Fatalf("second Add = %v, want ErrExists", err)
	}
	got, err := kc.List(ctx)
	if err != nil || len(got) != 1 || got[0].ID != KubeClusterID("lab") {
		t.Fatalf("List = %+v, %v", got, err)
	}
	// The CA rotation's view of sealed secrets leaves the tombstone out.
	sealed, err := s.CARotations().Sealed(ctx)
	if err != nil || len(sealed) != 1 || sealed[0].ID != KubeClusterID("lab") {
		t.Fatalf("Sealed = %+v, %v", sealed, err)
	}
}

func TestNaturalIDs(t *testing.T) {
	if a, b := KubeClusterID("lab"), KubeClusterID("lab"); a != b || a == KubeClusterID("lab2") {
		t.Fatal("KubeClusterID is not a function of the name")
	}
	if KubeClusterID("lab") == ProxmoxServerID("lab") {
		t.Fatal("ids of two tables collide")
	}
	if id := PanelLinkID("secret"); len(id) != 16 || strings.Contains(id, "secret") || id != PanelLinkID("secret") {
		t.Fatalf("PanelLinkID = %q", id)
	}
}
