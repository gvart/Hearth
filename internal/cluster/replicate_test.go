// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hlc"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// apNet is an in-process sharded cluster: members reach each other over
// net.Pipe, and a test takes members down or cuts links.
type apNet struct {
	mu      sync.Mutex
	members map[string]*apMember
	down    map[string]bool
	// crashed members refuse connections but still look alive in the
	// gossip, as in the moments after a crash.
	crashed map[string]bool
	cut     map[[2]string]bool
}

type apMember struct {
	id    string
	rep   *Replicator
	st    *store.Store
	hints *Hints
}

type apPeers struct {
	net  *apNet
	self string
}

func (p apPeers) Members() []MemberInfo {
	p.net.mu.Lock()
	defer p.net.mu.Unlock()
	var out []MemberInfo
	for id := range p.net.members {
		state := MemberAlive
		if p.net.down[id] || p.net.cut[[2]string{p.self, id}] {
			state = MemberDead
		}
		out = append(out, MemberInfo{ID: id, Roles: HubRoles, State: state})
	}
	return out
}

func (p apPeers) DialReplica(_ context.Context, id string) (net.Conn, error) {
	p.net.mu.Lock()
	m, ok := p.net.members[id]
	blocked := p.net.down[id] || p.net.crashed[id] || p.net.down[p.self] || p.net.cut[[2]string{p.self, id}]
	p.net.mu.Unlock()
	if !ok || blocked {
		return nil, fmt.Errorf("dial %s: unreachable", id)
	}
	a, b := net.Pipe()
	go m.rep.ServeConn(b, p.self)
	return a, nil
}

// newAPNet starts members ids with replication factor n (0: default).
func newAPNet(t *testing.T, n int, ids ...string) *apNet {
	t.Helper()
	an := &apNet{members: map[string]*apMember{}, down: map[string]bool{}, crashed: map[string]bool{}, cut: map[[2]string]bool{}}
	for _, id := range ids {
		an.add(t, n, id)
	}
	return an
}

func (an *apNet) add(t *testing.T, n int, id string) *apMember {
	t.Helper()
	hints, err := OpenHints(t.Context(), filepath.Join(t.TempDir(), HintsFile), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hints.Close() })
	rep, err := NewReplicator(ReplicatorConfig{
		NodeID: id, Peers: apPeers{net: an, self: id}, Replicas: n, Hints: hints,
		RequestTimeout: 2 * time.Second, AntiEntropyEvery: time.Hour, HintsEvery: time.Hour, GCEvery: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.Open(t, store.WithShards(rep), store.WithApplier(rep.Bind), store.WithOrigin(id))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = rep.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	m := &apMember{id: id, rep: rep, st: st, hints: hints}
	an.mu.Lock()
	an.members[id] = m
	an.mu.Unlock()
	return m
}

func (an *apNet) setDown(id string, down bool) {
	an.mu.Lock()
	defer an.mu.Unlock()
	an.down[id] = down
}

// split cuts every link between the groups a and b, or heals them.
func (an *apNet) split(a, b []string, cut bool) {
	an.mu.Lock()
	defer an.mu.Unlock()
	for _, x := range a {
		for _, y := range b {
			an.cut[[2]string{x, y}], an.cut[[2]string{y, x}] = cut, cut
		}
	}
}

func (an *apNet) m(id string) *apMember {
	an.mu.Lock()
	defer an.mu.Unlock()
	return an.members[id]
}

// keyOwnedBy returns a key whose first n replicas are exactly owners, in
// any order.
func keyOwnedBy(t *testing.T, ids []string, n int, prefix string, owners ...string) string {
	t.Helper()
	ring := NewRing(ids)
	for i := range 100000 {
		k := prefix + strconv.Itoa(i)
		got := slices.Clone(ring.Owners(store.BucketOf(store.Token(k)), n))
		slices.Sort(got)
		want := slices.Clone(owners)
		slices.Sort(want)
		if slices.Equal(got, want) {
			return k
		}
	}
	t.Fatalf("no key owned by %v", owners)
	return ""
}

func device(id, name string) store.Device {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return store.Device{ID: id, Name: name, Hostname: id, OS: "linux", Arch: "arm64", Facts: json.RawMessage(`{}`),
		FirstSeen: now, LastSeen: now, Status: store.StatusOnline}
}

// localDevice reads device id from member m's own database, bypassing the
// shards.
func localDevice(t *testing.T, m *apMember, id string) (string, bool) {
	t.Helper()
	rows, err := m.st.ReadLocal(t.Context(), `SELECT name FROM devices WHERE id = ?`, store.Values{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Vals) == 0 {
		return "", false
	}
	s, _ := rows.Vals[0][0].(string)
	return s, true
}

func apEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRingPlacementStable(t *testing.T) {
	before := NewRing([]string{"a", "b", "c"})
	after := NewRing([]string{"a", "b", "c", "d"})
	moved := 0
	for b := range store.ShardBuckets {
		o1, o2 := before.Owners(b, 2), after.Owners(b, 2)
		if slices.Equal(o1, o2) {
			continue
		}
		moved++
		if !slices.Contains(o2, "d") {
			t.Fatalf("bucket %d moved from %v to %v without the new member", b, o1, o2)
		}
	}
	// A fourth member takes about half of the buckets' second replicas
	// at most: nothing near a full reshuffle.
	if moved == 0 || moved > store.ShardBuckets*3/4 {
		t.Errorf("%d of %d buckets moved", moved, store.ShardBuckets)
	}
	removed := NewRing([]string{"a", "c"})
	for b := range store.ShardBuckets {
		o1, o2 := before.Owners(b, 2), removed.Owners(b, 2)
		if !slices.Equal(o1, o2) && !slices.Contains(o1, "b") {
			t.Fatalf("bucket %d moved from %v to %v though b did not hold it", b, o1, o2)
		}
	}
	// Placement depends on the member ids only.
	if !slices.Equal(NewRing([]string{"c", "a", "b"}).Preference(42), before.Preference(42)) {
		t.Error("ring depends on member order")
	}
	// Segments tile the bucket space and keep one preference each.
	var next int
	for _, s := range before.Segments() {
		if s.Start != next || s.End <= s.Start {
			t.Fatalf("segment %+v after %d", s, next)
		}
		if !slices.Equal(before.Preference(s.Start), before.Preference(s.End-1)) {
			t.Fatalf("segment %+v has two preference lists", s)
		}
		next = s.End
	}
	if next != store.ShardBuckets {
		t.Fatalf("segments end at %d", next)
	}
}

func TestWritesReachReplicasAndReadsRoute(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	// A device a does not hold: the write is forwarded, the read routed.
	id := keyOwnedBy(t, ids, 2, "dev", "b", "c")
	if err := an.m("a").st.Devices().Upsert(ctx, device(id, "far")); err != nil {
		t.Fatal(err)
	}
	if _, ok := localDevice(t, an.m("a"), id); ok {
		t.Error("a holds a row it is no replica of")
	}
	apEventually(t, "both replicas", func() bool {
		_, ok1 := localDevice(t, an.m("b"), id)
		_, ok2 := localDevice(t, an.m("c"), id)
		return ok1 && ok2
	})
	for _, m := range ids {
		d, err := an.m(m).st.Devices().Get(ctx, id)
		if err != nil || d.Name != "far" {
			t.Fatalf("%s: Get = %+v, %v", m, d, err)
		}
	}
	// The list merges every member's rows, each once, by id.
	for i := range 10 {
		if err := an.m(ids[i%3]).st.Devices().Upsert(ctx, device(fmt.Sprintf("d%02d", i), "n")); err != nil {
			t.Fatal(err)
		}
	}
	list, err := an.m("c").st.Devices().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 11 || list[0].ID != "d00" || list[10].ID != id {
		t.Errorf("list = %d devices, first %s", len(list), list[0].ID)
	}
}

func TestCriticalWriteFailsFast(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 3, ids...)
	an.setDown("b", true)
	an.setDown("c", true)
	_, err := an.m("a").st.Audit().Append(ctx, store.AuditEntry{
		TS: time.Now(), ActorKind: "user", ActorID: "admin", Action: "device.exec", Decision: "allow", Result: "ok",
	})
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("critical write with 1 of 3 replicas: err = %v, want ErrUnavailable", err)
	}
	rows, err := an.m("a").st.ReadLocal(ctx, `SELECT count(*) FROM audit_log`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Vals[0][0].(int64) != 0 {
		t.Error("a failed critical write was written")
	}
	// A non-critical write takes W = 1 and goes on.
	if err := an.m("a").st.Devices().Upsert(ctx, device("solo", "n")); err != nil {
		t.Errorf("W=1 write with one replica: %v", err)
	}
	// With two of three up, the critical write takes W = 2.
	an.setDown("b", false)
	if _, err := an.m("a").st.Audit().Append(ctx, store.AuditEntry{
		TS: time.Now(), ActorKind: "user", ActorID: "admin", Action: "device.exec", Decision: "allow", Result: "ok",
	}); err != nil {
		t.Fatalf("critical write with 2 of 3 replicas: %v", err)
	}
}

// With N=2 and a replica down, a critical write goes to a stand-in and
// the down replica gets it from the hints once back: nothing is lost.
func TestHintedHandoff(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	id := keyOwnedBy(t, ids, 2, "dev", "a", "b")
	an.setDown("b", true)
	if err := an.m("a").st.Devices().Upsert(ctx, device(id, "v1")); err != nil {
		t.Fatal(err)
	}
	if err := an.m("a").st.Certs().Create(ctx, "serial-1", id); err != nil {
		t.Fatalf("critical write with a stand-in: %v", err)
	}
	if n, _ := an.m("a").hints.Count(ctx, "b"); n == 0 {
		t.Fatal("no hint kept for the down replica")
	}
	// The stand-in holds the rows meanwhile, so reads find them.
	if err := an.m("c").st.Certs().Check(ctx, "serial-1", id); err != nil {
		t.Errorf("check on a member while b is down: %v", err)
	}
	an.setDown("b", false)
	an.m("a").rep.deliverHints(ctx)
	if name, ok := localDevice(t, an.m("b"), id); !ok || name != "v1" {
		t.Fatalf("b after hints: %q %v", name, ok)
	}
	if n, _ := an.m("a").hints.Count(ctx, "b"); n != 0 {
		t.Errorf("%d hints left after delivery", n)
	}
	rows, _ := an.m("b").st.ReadLocal(ctx, `SELECT count(*) FROM certs WHERE serial = 'serial-1'`, nil)
	if rows.Vals[0][0].(int64) != 1 {
		t.Error("the certificate did not reach b")
	}
}

// A list that sees two versions of a row repairs the stale replica.
func TestReadRepair(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	id := keyOwnedBy(t, ids, 2, "dev", "a", "b")
	if err := an.m("c").st.Devices().Upsert(ctx, device(id, "old")); err != nil {
		t.Fatal(err)
	}
	apEventually(t, "replicas", func() bool { _, ok := localDevice(t, an.m("b"), id); return ok })
	// a takes a newer version that never reached b.
	if _, err := an.m("a").st.ApplyLocal(ctx, store.ReportFacts{
		Stamp: store.Stamp{HLC: hlc.New(time.Now()), Origin: "a"}, ID: id, Hostname: id, Facts: `{}`, Now: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := an.m("c").st.Devices().List(ctx); err != nil {
		t.Fatal(err)
	}
	apEventually(t, "read repair", func() bool {
		ra, _ := an.m("a").st.ReadLocal(ctx, `SELECT _hlc FROM devices WHERE id = ?`, store.Values{id})
		rb, _ := an.m("b").st.ReadLocal(ctx, `SELECT _hlc FROM devices WHERE id = ?`, store.Values{id})
		return len(ra.Vals) == 1 && len(rb.Vals) == 1 && ra.Vals[0][0] == rb.Vals[0][0]
	})
}

// Two replicas that diverged, both ways, converge in one anti-entropy
// round, children after their parents.
func TestAntiEntropyConverges(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b"}
	an := newAPNet(t, 2, ids...)
	stamp := func(o string) store.Stamp { return store.Stamp{HLC: hlc.New(time.Now()), Origin: o} }
	// Rows written to one database each, never replicated.
	for i := range 20 {
		m := an.m(ids[i%2])
		d := fmt.Sprintf("dev%02d", i)
		if _, err := m.st.ApplyLocal(ctx, store.UpsertDevice{Stamp: stamp(m.id), ID: d, Name: d, Facts: "{}", Labels: "{}",
			Status: store.StatusOnline}); err != nil {
			t.Fatal(err)
		}
		if _, err := m.st.ApplyLocal(ctx, store.CreateCert{Stamp: stamp(m.id), Serial: "s" + d, DeviceID: d}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := an.m("a").st.ApplyLocal(ctx, store.SetPasswordHash{Stamp: stamp("a"), Hash: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := an.m("a").rep.SyncWith(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	dump := func(m *apMember) string {
		var out []string
		for _, q := range []string{
			`SELECT id, name, _hlc, _origin FROM devices ORDER BY id`,
			`SELECT serial, device_id, _hlc FROM certs ORDER BY serial`,
			`SELECT password_hash, _hlc FROM admin`,
		} {
			r, err := m.st.ReadLocal(ctx, q, nil)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(r.Vals)
			out = append(out, string(b))
		}
		return fmt.Sprint(out)
	}
	if da, db := dump(an.m("a")), dump(an.m("b")); da != db {
		t.Fatalf("diverged after a round:\n a %s\n b %s", da, db)
	}
	all := make([]int, store.ShardBuckets)
	for i := range all {
		all[i] = i
	}
	if !slices.Equal(an.m("a").st.BucketDigests(store.SpaceShard, all), an.m("b").st.BucketDigests(store.SpaceShard, all)) {
		t.Error("digests differ after a round")
	}
}

// A split leaves both sides writable; once healed, they converge.
func TestSplitAndHeal(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	an.split([]string{"a"}, []string{"b", "c"}, true)
	for i := range 6 {
		side := "a"
		if i%2 == 1 {
			side = "b"
		}
		if err := an.m(side).st.Devices().Upsert(ctx, device(fmt.Sprintf("split%d", i), side)); err != nil {
			t.Fatalf("write on side %s during the split: %v", side, err)
		}
	}
	an.split([]string{"a"}, []string{"b", "c"}, false)
	for _, m := range ids {
		an.m(m).rep.deliverHints(ctx)
	}
	for _, m := range ids {
		an.m(m).rep.antiEntropy(ctx)
	}
	var lists []string
	for _, m := range ids {
		l, err := an.m(m).st.Devices().List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(l)
		lists = append(lists, string(b))
	}
	if lists[0] != lists[1] || lists[1] != lists[2] {
		t.Fatalf("lists differ after heal:\n%s", lists)
	}
	var got []store.Device
	_ = json.Unmarshal([]byte(lists[0]), &got)
	if len(got) != 6 {
		t.Errorf("%d devices after heal, want 6", len(got))
	}
}

func TestAuditPagesAcrossMembers(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	for i := range 12 {
		if _, err := an.m(ids[i%3]).st.Audit().Append(ctx, store.AuditEntry{
			TS: time.Now(), ActorKind: "user", ActorID: "admin", Action: fmt.Sprintf("act%02d", i), Decision: "allow", Result: "ok",
		}); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	var cursor int64
	for {
		page, err := an.m("b").st.Audit().Query(ctx, store.AuditFilter{Before: cursor}, 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			got = append(got, e.Action)
		}
		cursor = page[len(page)-1].ID
	}
	if len(got) != 12 || got[0] != "act11" || got[11] != "act00" {
		t.Errorf("pages = %v", got)
	}
}

// Negative: a merge stamped beyond the skew bound is refused whole, and a
// hub that is not a member gets nothing.
func TestReplicationRefusals(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 2, "a", "b")
	future := hlc.New(time.Now().Add(time.Hour))
	ok := store.Mutation{Table: "devices", HLC: hlc.New(time.Now()), Origin: "a", Row: map[string]any{
		"id": "x", "name": "x", "hostname": "", "os": "", "arch": "", "facts": "{}", "labels": "{}",
		"first_seen": int64(0), "last_seen": int64(0), "status": "online", "boot_time": nil,
	}}
	skewed := ok
	skewed.Row = map[string]any{"id": "y", "name": "y", "hostname": "", "os": "", "arch": "", "facts": "{}", "labels": "{}",
		"first_seen": int64(0), "last_seen": int64(0), "status": "online", "boot_time": nil}
	skewed.HLC = future
	_, err := an.m("a").rep.call(ctx, "b", apRequest{Op: opMerge, Muts: []store.Mutation{ok, skewed}})
	if !errors.Is(err, hlc.ErrSkew) {
		t.Fatalf("skewed batch: err = %v, want ErrSkew", err)
	}
	if _, found := localDevice(t, an.m("b"), "x"); found {
		t.Error("part of a refused batch was written")
	}
	// A hub with a valid certificate but no membership.
	c1, c2 := net.Pipe()
	go an.m("b").rep.ServeConn(c2, "intruder")
	if err := writeFrame(c1, apRequest{Op: opRead, Query: `SELECT * FROM admin`}); err != nil {
		t.Fatal(err)
	}
	var resp apResponse
	if err := readFrame(c1, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Kind != "not_member" || resp.Rows != nil {
		t.Errorf("non-member answer = %+v", resp)
	}
	_ = c1.Close()
	// A read cannot write.
	if _, err := an.m("a").rep.call(ctx, "b", apRequest{Op: opRead, Query: `DELETE FROM devices`}); err == nil {
		t.Error("a read request ran a write")
	}
}

func TestGCAndRejoinEmpty(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 1, "a")
	m := an.m("a")
	old := hlc.New(time.Now().Add(-8 * 24 * time.Hour))
	if _, err := m.st.ApplyLocal(ctx, store.CreatePanel{Stamp: store.Stamp{HLC: old, Origin: "a"}, ID: "p", Name: "p", Widgets: "[]"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.st.ApplyLocal(ctx, store.DeletePanel{Stamp: store.Stamp{HLC: old + 1, Origin: "a"}, ID: "p"}); err != nil {
		t.Fatal(err)
	}
	m.rep.gc(ctx)
	rows, _ := m.st.ReadLocal(ctx, `SELECT count(*) FROM panels`, nil)
	if rows.Vals[0][0].(int64) != 0 {
		t.Error("an old tombstone survived the gc")
	}

	path := filepath.Join(t.TempDir(), "last-contact")
	now := time.Now()
	if err := CheckRejoin(path, true, now); err != nil {
		t.Errorf("no record yet: %v", err)
	}
	if err := writeLastContact(path, now.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := CheckRejoin(path, true, now); !errors.Is(err, ErrRejoinEmpty) {
		t.Errorf("away 8 days with rows: err = %v, want ErrRejoinEmpty", err)
	}
	if err := CheckRejoin(path, false, now); err != nil {
		t.Errorf("away 8 days, empty: %v", err)
	}
	if err := writeLastContact(path, now.Add(-6*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := CheckRejoin(path, true, now); err != nil {
		t.Errorf("away 6 days: %v", err)
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckRejoin(path, true, now); err == nil {
		t.Error("an unreadable record was accepted")
	}
}

// A replica that crashed a moment ago, still alive in the gossip, does not
// fail a critical write: the rows go to the next live stand-in, and the
// crashed replica gets a hint.
func TestCriticalWriteFallsBackToStandIn(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	id := keyOwnedBy(t, ids, 2, "dev", "a", "b")
	if err := an.m("a").st.Devices().Upsert(ctx, device(id, "d")); err != nil {
		t.Fatal(err)
	}
	an.mu.Lock()
	an.crashed["b"] = true
	an.mu.Unlock()
	if err := an.m("a").st.Certs().Create(ctx, "serial-x", id); err != nil {
		t.Fatalf("critical write with a just-crashed replica: %v", err)
	}
	rows, _ := an.m("c").st.ReadLocal(ctx, `SELECT count(*) FROM certs WHERE serial = 'serial-x'`, nil)
	if rows.Vals[0][0].(int64) != 1 {
		t.Error("the stand-in did not take the write")
	}
	if n, _ := an.m("a").hints.Count(ctx, "b"); n == 0 {
		t.Error("no hint kept for the crashed replica")
	}
	// Forwarded writes, and audit entries, on any member go on too.
	for i := range 20 {
		k := fmt.Sprintf("tok%d", i)
		if err := an.m(ids[i%3]).st.Tokens().Create(ctx, k, nil, time.Now().Add(time.Hour)); err != nil && ids[i%3] != "b" {
			t.Fatalf("token %d on %s: %v", i, ids[i%3], err)
		}
		if _, err := an.m("c").st.Audit().Append(ctx, store.AuditEntry{TS: time.Now(), ActorKind: "user", ActorID: "a",
			Action: k, Decision: "allow", Result: "ok"}); err != nil {
			t.Fatalf("audit %d: %v", i, err)
		}
	}
}

func TestSingleMemberWorks(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 0, "solo")
	m := an.m("solo")
	if m.rep.N() != 1 {
		t.Errorf("N = %d, want 1", m.rep.N())
	}
	if _, err := m.st.Audit().Append(ctx, store.AuditEntry{TS: time.Now(), ActorKind: "user", ActorID: "a",
		Action: "x", Decision: "allow", Result: "ok"}); err != nil {
		t.Fatalf("critical write alone: %v", err)
	}
	if err := m.st.Devices().Upsert(ctx, device("d", "d")); err != nil {
		t.Fatal(err)
	}
	if l, err := m.st.Devices().List(ctx); err != nil || len(l) != 1 {
		t.Fatalf("list = %v, %v", l, err)
	}
}

// A data dir runs in one cluster mode only.
func TestCheckMode(t *testing.T) {
	raftDir, apDir, fresh := t.TempDir(), t.TempDir(), t.TempDir()
	for _, f := range []struct{ dir, name, body string }{
		{raftDir, boltFile, ""},
		{apDir, apModeFile, "ap\n"},
	} {
		if err := os.MkdirAll(filepath.Join(f.dir, RaftDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.dir, RaftDir, f.name), []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		dir, mode string
		ok        bool
	}{
		{fresh, "ap", true}, {fresh, "raft", true},
		{apDir, "ap", true}, {apDir, "raft", false},
		{raftDir, "raft", true}, {raftDir, "ap", false},
	} {
		err := CheckMode(tt.dir, tt.mode)
		if (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrModeMismatch)) {
			t.Errorf("CheckMode(%s, %s) = %v", tt.dir, tt.mode, err)
		}
	}
	if !IsAPMember(apDir) || IsAPMember(raftDir) {
		t.Error("IsAPMember")
	}
}
