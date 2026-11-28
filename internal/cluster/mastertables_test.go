// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hlc"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// The secrets of the rows forgeGrants writes.
const (
	forgedSession = "forged-session"
	forgedMCP     = "forged-mcp-token"
	forgedDash    = "forged-dashboard-token"
	forgedLink    = "forged-panel-link"
)

func secretHash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// forgeGrants writes, on mem's own database only, a sign-in session, an MCP
// token, a dashboard token, a panel and its share link, stamped as if
// master m wrote them, and returns their rows: what a compromised storage
// member would send, or answer with.
func forgeGrants(t *testing.T, mem *apMember) []store.Mutation {
	t.Helper()
	now := time.Now()
	ms := now.UnixMilli()
	st := func(i uint64) store.Stamp { return store.Stamp{HLC: hlc.New(now) + hlc.Timestamp(i), Origin: "m"} }
	var out []store.Mutation
	for _, cmd := range []store.Command{
		store.CreateSession{Stamp: st(0), Hash: secretHash(forgedSession), Now: ms, ExpiresAt: ms + time.Hour.Milliseconds()},
		store.CreateMCPToken{Stamp: st(1), Name: "evil", Hash: secretHash(forgedMCP), Scope: "write", CreatedAt: ms},
		store.CreateDashboardToken{Stamp: st(2), ID: "evil", Name: "evil", Hash: secretHash(forgedDash), CreatedAt: ms},
		store.CreatePanel{Stamp: st(3), ID: "evil", Name: "evil", Widgets: "[]", At: ms},
		store.CreatePanelLink{Stamp: st(4), ID: "evil", PanelID: "evil", Hash: secretHash(forgedLink), CreatedAt: ms},
	} {
		_, muts, err := mem.st.ApplyLocalMutations(t.Context(), cmd)
		if err != nil {
			t.Fatalf("forge %s: %v", cmd.Op(), err)
		}
		out = append(out, muts...)
	}
	for _, m := range out {
		if !store.MasterTable(m.Table) {
			t.Fatalf("forged a row of %s, not a master table", m.Table)
		}
	}
	return out
}

// masterRowCount counts the rows of the master tables in st's own
// database, tombstones included.
func masterRowCount(t *testing.T, st *store.Store) int {
	t.Helper()
	n := 0
	for _, table := range store.MasterTables() {
		rows, err := st.ReadLocal(t.Context(), `SELECT COUNT(*) FROM `+table, nil)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := rows.Vals[0][0].(int64)
		n += int(c)
	}
	return n
}

// grantsRefused fails unless none of the forged secrets grants anything on
// st: the session, the MCP and dashboard tokens and the panel link.
func grantsRefused(t *testing.T, who string, st *store.Store) {
	t.Helper()
	ctx, now := t.Context(), time.Now()
	if _, err := st.Admin().CheckSession(ctx, forgedSession, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s: forged session: %v, want not found", who, err)
	}
	if _, err := st.MCPTokens().Check(ctx, forgedMCP); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s: forged MCP token: %v, want not found", who, err)
	}
	if _, err := st.DashboardTokens().Check(ctx, forgedDash, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s: forged dashboard token: %v, want not found", who, err)
	}
	if _, _, err := st.Panels().CheckLink(ctx, forgedLink, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s: forged panel link: %v, want not found", who, err)
	}
}

// makeGrants writes, on master mem through its store, a session, an MCP and
// a dashboard token, a panel and a share link.
func makeGrants(t *testing.T, mem *apMember) {
	t.Helper()
	ctx, now := t.Context(), time.Now()
	if err := mem.st.Admin().CreateSession(ctx, "real-session", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := mem.st.MCPTokens().Create(ctx, "real", "real-mcp", "write", now); err != nil {
		t.Fatal(err)
	}
	if err := mem.st.DashboardTokens().Create(ctx, store.DashboardToken{ID: "real", Name: "real", CreatedAt: now}, "real-dash"); err != nil {
		t.Fatal(err)
	}
	if err := mem.st.Panels().Create(ctx, store.Panel{ID: "real", Name: "real", Widgets: "[]", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := mem.st.Panels().CreateLink(ctx, store.PanelLink{ID: "real", PanelID: "real", CreatedAt: now}, "real-link"); err != nil {
		t.Fatal(err)
	}
}

// TestMasterRowsStayOnMasters: the rows only masters hold, written on a
// master, reach no storage-only member, by the write's copies or by
// anti-entropy, though both say on the gossip that they are masters; the
// master's critical writes of them still succeed, and it reads them on its
// own copy.
func TestMasterRowsStayOnMasters(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	makeGrants(t, an.m("m"))
	for _, p := range [][2]string{{"m", "s"}, {"m", "s2"}, {"s", "m"}, {"s2", "m"}} {
		if err := an.m(p[0]).rep.SyncWith(ctx, p[1]); err != nil {
			t.Fatalf("anti-entropy of %s with %s: %v", p[0], p[1], err)
		}
	}
	// The rows withheld from s and s2, which never prove the key, stay
	// hinted, in place: delivering them again sends nothing and adds none.
	an.m("m").rep.deliverHints(ctx)
	kept := map[string]int{}
	for _, id := range []string{"s", "s2"} {
		n, err := an.m("m").hints.Count(ctx, id)
		if err != nil || n == 0 {
			t.Fatalf("hints for %s: %d, %v; want the withheld rows kept", id, n, err)
		}
		kept[id] = n
	}
	an.m("m").rep.deliverHints(ctx)
	for _, id := range []string{"s", "s2"} {
		if n := masterRowCount(t, an.m(id).st); n != 0 {
			t.Fatalf("storage-only %s holds %d master rows", id, n)
		}
		if n, err := an.m("m").hints.Count(ctx, id); err != nil || n != kept[id] {
			t.Fatalf("hints for %s after another delivery: %d, %v; want %d", id, n, err, kept[id])
		}
	}
	m := an.m("m").st
	if _, err := m.Admin().CheckSession(ctx, "real-session", time.Now()); err != nil {
		t.Fatalf("the master's session: %v", err)
	}
	if _, err := m.MCPTokens().Check(ctx, "real-mcp"); err != nil {
		t.Fatalf("the master's MCP token: %v", err)
	}
	if _, err := m.DashboardTokens().Check(ctx, "real-dash", time.Now()); err != nil {
		t.Fatalf("the master's dashboard token: %v", err)
	}
	if _, _, err := m.Panels().CheckLink(ctx, "real-link", time.Now()); err != nil {
		t.Fatalf("the master's panel link: %v", err)
	}
	// A master off the ring, the only one: every master row is its alone,
	// and its writes still succeed.
	an.mu.Lock()
	an.roles["m"] = masterOnly
	an.mu.Unlock()
	an.m("m").rep.SetLocal(false, false)
	if err := m.Admin().DeleteSession(ctx, "real-session"); err != nil {
		t.Fatalf("sign out on a master off the ring: %v", err)
	}
}

// TestForgedMasterRowsRefused: rows of the master tables a storage-only
// member forged never reach a master, nor another storage member, by any
// path, and a master never asks a storage member for them: a merge, a
// command to coordinate, a hint, anti-entropy (also of the master rows'
// own digests), a fetch, a read, a read repair, a revocation, a backup.
func TestForgedMasterRowsRefused(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	forged := forgeGrants(t, an.m("s"))
	refs := []store.RowRef{
		{Table: "sessions", Key: store.Values{secretHash(forgedSession)}},
		{Table: "mcp_tokens", Key: store.Values{"evil"}},
		{Table: "dashboard_tokens", Key: store.Values{"evil"}},
		{Table: "panels", Key: store.Values{"evil"}},
		{Table: "panel_links", Key: store.Values{"evil"}},
	}
	if got, err := an.m("s").st.ReadRows(ctx, refs); err != nil || len(got) != len(refs) {
		t.Fatalf("the forged rows on s: %d, %v", len(got), err)
	}

	// A merge (a write's copy, a hand-off and a read repair arrive so): m
	// refuses it. s2 does too, sent past the check of s's own calls, which
	// send master rows to no member that did not prove the key.
	if _, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opMerge, Muts: forged}); !errors.Is(err, errNotMaster) {
		t.Fatalf("merge of forged master rows into m: %v, want errNotMaster", err)
	}
	if resp := an.m("s2").rep.handle(ctx, "s", false, apRequest{Op: opMerge, Muts: forged}); resp.Error == nil ||
		!errors.Is(apError(resp.Error), errNotMaster) {
		t.Fatalf("merge of forged master rows into s2: %+v, want errNotMaster", resp.Error)
	}
	if _, err := an.m("s").rep.call(ctx, "s2", apRequest{Op: opMerge, Muts: forged}); err != nil {
		t.Fatalf("merge into s2 through s's calls: %v, want nothing sent", err)
	}
	// A command to coordinate.
	b, err := store.EncodeCommand(store.CreateSession{Hash: secretHash(forgedSession), Now: 1, ExpiresAt: 1 << 50})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opApply, Cmd: b}); !errors.Is(err, errNotMaster) {
		t.Fatalf("a session for m to coordinate: %v, want errNotMaster", err)
	}
	// Its own store writes none either.
	if err := an.m("s").st.Admin().CreateSession(ctx, "s-session", time.Now(), time.Now().Add(time.Hour)); !errors.Is(err, errNotMaster) {
		t.Fatalf("a sign-in on a storage member: %v, want errNotMaster", err)
	}
	// A hint.
	if err := an.m("s").hints.Add("m", forged); err != nil {
		t.Fatal(err)
	}
	an.m("s").rep.deliverHints(ctx)
	// Anti-entropy, both ways and through a promotion's catch-up.
	for _, p := range [][2]string{{"m", "s"}, {"s", "m"}, {"s2", "s"}, {"s", "s2"}} {
		if err := an.m(p[0]).rep.SyncWith(ctx, p[1]); err != nil {
			t.Fatalf("anti-entropy of %s with %s: %v", p[0], p[1], err)
		}
	}
	an.m("s2").rep.SetLocal(true, true)
	an.m("s2").rep.CatchUp(ctx)
	// The master rows' digests are compared with masters only.
	all := []bucketRange{{0, store.GlobalBuckets}}
	for _, op := range []string{opTree, opLeaves} {
		if _, err := an.m("s").rep.call(ctx, "m", apRequest{Op: op, Space: store.SpaceMaster, Ranges: all}); !errors.Is(err, errNotMaster) {
			t.Fatalf("%s of the master rows from s: %v, want errNotMaster", op, err)
		}
	}
	if err := an.m("m").rep.syncSpace(ctx, "s", store.SpaceMaster, all, false); err != nil {
		t.Fatalf("a sync of the master rows with s: %v", err)
	}
	// A fetch, a read repair and a revocation naming s as the writer.
	if ms, err := an.m("m").rep.fetch(ctx, "s", refs); err != nil || len(ms) != 0 {
		t.Fatalf("fetch from s: %d rows, %v; want none", len(ms), err)
	}
	if err := an.m("m").rep.repair(ctx, refs); err != nil {
		t.Fatal(err)
	}
	if err := an.m("m").rep.takeRevocation(ctx, revocationMsg{Kind: msgRevoked, From: "s", Refs: refs}); err != nil {
		t.Fatal(err)
	}
	// A backup.
	dst := storetest.Open(t, store.WithDigest())
	if err := an.m("m").rep.PullAll(ctx, dst); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if n := masterRowCount(t, dst); n != 0 {
		t.Fatalf("the backup took %d forged master rows", n)
	}

	for _, id := range []string{"m", "s2"} {
		if n := masterRowCount(t, an.m(id).st); n != 0 {
			t.Fatalf("%s took %d forged master rows", id, n)
		}
	}
	// The master checks every grant on its own copy: s, which holds the
	// forged rows, is not asked.
	grantsRefused(t, "m", an.m("m").st)

	// Nor does a master serve its master rows to s: not by a fetch, a read
	// naming them, however spelled, or the master rows' digests.
	makeGrants(t, an.m("m"))
	refsMine := []store.RowRef{{Table: "sessions", Key: store.Values{secretHash("real-session")}}}
	if mine, err := an.m("m").st.ReadRows(ctx, refsMine); err != nil || len(mine) != 1 {
		t.Fatalf("m's session: %v, %v", mine, err)
	}
	resp, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opFetch, Refs: refsMine})
	if err != nil || len(resp.Muts) != 0 {
		t.Fatalf("s fetched %d of m's master rows, %v; want none", len(resp.Muts), err)
	}
	for _, q := range []string{`SELECT hash FROM sessions`, `SELECT * FROM "MCP_Tokens"`, `SELECT id FROM [panel_links]`} {
		if _, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opRead, Query: q}); !errors.Is(err, errNotMaster) {
			t.Fatalf("s read %q on m: %v, want errNotMaster", q, err)
		}
	}
	// Past the check of the query's text, SQLite refuses the raw pages.
	for _, q := range []string{`SELECT data FROM sqlite_dbpage`, `SELECT count(*) FROM dbstat`} {
		if _, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opRead, Query: q}); err == nil || !strings.Contains(err.Error(), store.ErrReadRefused.Error()) {
			t.Fatalf("s read %q on m: %v, want refused", q, err)
		}
		if _, err := an.m("m").st.ReadLocal(ctx, q, nil); err != nil {
			t.Fatalf("%q on m's own connection: %v", q, err)
		}
	}
	if rows, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opRead, Query: `SELECT id FROM devices`}); err != nil || rows.Rows == nil {
		t.Fatalf("s's read of the devices on m: %v, %v", rows.Rows, err)
	}
	if _, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opRows, Space: store.SpaceMaster, Buckets: []int{0}}); !errors.Is(err, errNotMaster) {
		t.Fatalf("s read the master rows' digests on m: %v, want errNotMaster", err)
	}
}

// TestKeylessMemberHoldsNoMasterRows: a member without the hub CA key drops
// master rows it is sent, even by a master (one that took it for a master
// on the gossip).
func TestKeylessMemberHoldsNoMasterRows(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	makeGrants(t, an.m("m"))
	rows, err := an.m("m").st.ReadRows(ctx, []store.RowRef{{Table: "sessions", Key: store.Values{secretHash("real-session")}}})
	if err != nil || len(rows) != 1 {
		t.Fatalf("m's session: %v, %v", rows, err)
	}
	if resp := an.m("s").rep.handle(ctx, "m", true, apRequest{Op: opMerge, Muts: rows}); resp.Error != nil {
		t.Fatal(resp.Error)
	}
	if n := masterRowCount(t, an.m("s").st); n != 0 {
		t.Fatalf("keyless s took %d master rows from a master", n)
	}
}

// TestPlaceMasterRows: as its store is bound, a member without the hub CA
// key deletes every master row, a master keeps them (the store reset those
// of a cluster's database as it migrated it, store.TestGrantsResetOnUpgrade);
// either drops, once, the hints of sessions, tokens and links kept from
// before this version, which would bring stale ones back elsewhere.
func TestPlaceMasterRows(t *testing.T) {
	ctx := t.Context()
	cases := []struct {
		name string
		key  bool
		want int // master rows left: makeGrants writes five
	}{
		{"master", true, 5},
		{"storage-only member", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, StateDir), 0o700); err != nil {
				t.Fatal(err)
			}
			ca := newTestCA(t)
			if !tc.key {
				if err := ca.DropKey(); err != nil {
					t.Fatal(err)
				}
			}
			hints, err := OpenHints(ctx, filepath.Join(dir, HintsFile), 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hints.Close() })
			n := &APNode{cfg: APConfig{DataDir: dir, CA: ca}, log: testLogger(t), hints: hints}
			st := storetest.Open(t, store.WithDigest())
			makeGrants(t, &apMember{id: "a", st: st})
			// A hint kept from before, of a session and a panel.
			rows, err := st.ReadRows(ctx, []store.RowRef{
				{Table: "sessions", Key: store.Values{secretHash("real-session")}},
				{Table: "panels", Key: store.Values{"real"}},
			})
			if err != nil || len(rows) != 2 {
				t.Fatalf("rows for a hint: %v, %v", rows, err)
			}
			hinted := func() int {
				_, ms, err := hints.Take(ctx, "b", 10)
				if err != nil {
					t.Fatal(err)
				}
				return len(ms)
			}
			if err := hints.Add("b", rows); err != nil {
				t.Fatal(err)
			}
			if err := n.placeMasterRows(ctx, st); err != nil {
				t.Fatal(err)
			}
			if got := masterRowCount(t, st); got != tc.want {
				t.Fatalf("master rows left: %d, want %d", got, tc.want)
			}
			if got := hinted(); got != 1 {
				t.Fatalf("hinted rows left: %d, want the panel's", got)
			}
			// Once: a hint of a session since is kept at the next start.
			if err := hints.Add("b", rows[:1]); err != nil {
				t.Fatal(err)
			}
			if err := n.placeMasterRows(ctx, st); err != nil {
				t.Fatal(err)
			}
			if got := hinted(); got != 2 {
				t.Fatalf("hinted rows after a second start: %d, want 2", got)
			}
		})
	}
}

// TestOneMasterWithStorageMembersDown: with one master and its storage-only
// members down, a sign-in and a password reset still succeed: neither waits
// for a quorum (#384). The reset ends the session from before, and the admin
// row waits in hints for the storage members.
func TestOneMasterWithStorageMembersDown(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	an.mu.Lock()
	an.roles["s"], an.roles["s2"] = storageOnly, storageOnly
	an.mu.Unlock()
	m := an.m("m").st
	if err := m.Admin().SetPasswordHash(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	an.setDown("s", true)
	an.setDown("s2", true)
	now := time.Now()
	if err := m.Admin().CreateSession(ctx, "alone", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("a sign-in on the one master: %v", err)
	}
	if err := m.Admin().SetPasswordHash(ctx, "h2"); err != nil {
		t.Fatalf("a reset with every storage member down: %v", err)
	}
	if h, err := m.Admin().PasswordHash(ctx); err != nil || h != "h2" {
		t.Fatalf("password hash = %q, %v; want h2", h, err)
	}
	if _, err := m.Admin().CheckSession(ctx, "alone", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session after the reset: %v, want not found", err)
	}
	for _, id := range []string{"s", "s2"} {
		if n, err := an.m("m").hints.Count(ctx, id); err != nil || n == 0 {
			t.Fatalf("hints for %s: %d, %v; want the admin row", id, n, err)
		}
	}
}

// TestMasterRowsGate: a master that has not compared the master tables'
// rows with another since it started reads none of them while another
// master that may prove the hub CA key is live; it reads them once it
// compared them, or once none is (a down one, or members that only say
// they are masters, are waited for by none).
// startCompared waits until r's comparison at the start (Run) is done
// and no longer holds pullMu: a read while it runs is refused at once, so
// a test that closes the gate and reads must not race it.
func startCompared(t *testing.T, r *Replicator) {
	t.Helper()
	apEventuallyTB(t, "the comparison at the start", func() bool {
		if !r.masterRowsSynced.Load() || !r.pullMu.TryLock() {
			return false
		}
		r.pullMu.Unlock()
		return true
	})
}

func TestMasterRowsGate(t *testing.T) {
	ctx := t.Context()
	t.Run("another master hung", func(t *testing.T) {
		an := newAPNetWith(t, 2, func(c *ReplicatorConfig) { c.LoneMasterWait = time.Hour }, "a", "b")
		a := an.m("a")
		if err := a.st.Admin().CreateSession(ctx, "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		a.rep.masterRowsSynced.Store(false)
		an.mu.Lock()
		an.hung["b"] = true
		an.mu.Unlock()
		a.rep.closePool()
		if _, err := a.st.Admin().CheckSession(ctx, "s", time.Now()); !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("session before the comparison: %v, want unavailable", err)
		}
		// b, which did not answer, is taken as down for a while: the next
		// read waits for it no more.
		an.mu.Lock()
		an.hung["b"] = false
		an.mu.Unlock()
		a.rep.clearSuspect("b")
		// A read while a comparison runs is refused at once (it does not
		// queue): it reads once one is done.
		apEventuallyTB(t, "a reads the session once b answers", func() bool {
			_, err := a.st.Admin().CheckSession(ctx, "s", time.Now())
			if err != nil && !errors.Is(err, store.ErrUnavailable) {
				t.Fatalf("session once b answers: %v", err)
			}
			return err == nil
		})
		if !a.rep.masterRowsSynced.Load() || a.rep.Uncompared() {
			t.Fatal("a did not record the comparison with b")
		}
	})
	t.Run("the other master down", func(t *testing.T) {
		an := newAPNet(t, 2, "a", "b")
		a := an.m("a")
		if err := a.st.Admin().CreateSession(ctx, "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"a", "b"} {
			if err := a.st.Hubs().RecordCert(ctx, "serial-"+id, id); err != nil {
				t.Fatal(err)
			}
		}
		startCompared(t, a.rep)
		a.rep.masterRowsSynced.Store(false)
		an.setDown("b", true)
		if _, err := a.st.Admin().CheckSession(ctx, "s", time.Now()); err != nil {
			t.Fatalf("session with the only other master down: %v", err)
		}
		if !a.rep.Uncompared() {
			t.Fatal("a read with no master to compare with, and does not say so")
		}
		// Once b is back and compared, a says so no more.
		an.setDown("b", false)
		if err := a.rep.SyncGlobal(ctx, "b"); err != nil {
			t.Fatal(err)
		}
		if a.rep.Uncompared() {
			t.Fatal("a still says it compared with no master after it did")
		}
	})
	t.Run("alone, within the wait", func(t *testing.T) {
		// A master that just started, or was just promoted, waits for the
		// gossip to find another master before it reads its own copy.
		an := newAPNetWith(t, 2, func(c *ReplicatorConfig) { c.LoneMasterWait = time.Hour }, "a", "b")
		a := an.m("a")
		if err := a.st.Admin().CreateSession(ctx, "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"a", "b"} {
			if err := a.st.Hubs().RecordCert(ctx, "serial-"+id, id); err != nil {
				t.Fatal(err)
			}
		}
		an.setDown("b", true)
		a.rep.closeMasterRows()
		if _, err := a.st.Admin().CheckSession(ctx, "s", time.Now()); !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("session within the wait, alone: %v, want unavailable", err)
		}
		if a.rep.Uncompared() {
			t.Fatal("a says it reads uncompared rows while it reads none")
		}
		// The refused read asked Run for a comparison, which retries
		// (pullMasterRows); within the wait none opens the rows.
		if a.rep.masterRowsSynced.Load() {
			t.Fatal("a opened its rows within the wait, alone")
		}
		a.rep.gateSince.Store(time.Now().Add(-2 * time.Hour).UnixNano())
		// A read while that comparison runs is refused at once (it does not
		// queue), so the one after the wait may come too early: it reads
		// once a round past the wait is done.
		apEventuallyTB(t, "a reads the session after the wait, alone", func() bool {
			_, err := a.st.Admin().CheckSession(ctx, "s", time.Now())
			if err != nil && !errors.Is(err, store.ErrUnavailable) {
				t.Fatalf("session after the wait, alone: %v", err)
			}
			return err == nil
		})
		if !a.rep.Uncompared() {
			t.Fatal("a read with no master to compare with, and does not say so")
		}
	})
	t.Run("never in a cluster", func(t *testing.T) {
		// A hub that never had another one waits for none.
		an := newAPNetWith(t, 1, func(c *ReplicatorConfig) { c.LoneMasterWait = time.Hour }, "a")
		a := an.m("a")
		if err := a.st.Admin().CreateSession(ctx, "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		startCompared(t, a.rep)
		a.rep.closeMasterRows()
		if _, err := a.st.Admin().CheckSession(ctx, "s", time.Now()); err != nil {
			t.Fatalf("session of a hub alone from the start: %v", err)
		}
		if a.rep.Uncompared() {
			t.Fatal("a hub alone from the start says it could not compare")
		}
	})
	t.Run("the only master, with storage members", func(t *testing.T) {
		// The gossip found the cluster, and no other master in it: no wait,
		// no banner, though the hubs' certificates say it is a cluster.
		an := newAPNetWith(t, 0, func(c *ReplicatorConfig) {
			c.LoneMasterWait = time.Hour
			if c.NodeID != "m" {
				c.Master = testMasterKey{}
			}
		}, "m", "s", "s2")
		an.mu.Lock()
		an.roles["s"], an.roles["s2"] = storageOnly, storageOnly
		an.mu.Unlock()
		m := an.m("m")
		for _, id := range []string{"m", "s", "s2"} {
			if err := m.st.Hubs().RecordCert(ctx, "serial-"+id, id); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.st.Admin().CreateSession(ctx, "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		startCompared(t, m.rep)
		m.rep.closeMasterRows()
		if _, err := m.st.Admin().CheckSession(ctx, "s", time.Now()); err != nil {
			t.Fatalf("session on the only master: %v", err)
		}
		if m.rep.Uncompared() {
			t.Fatal("the only master says it could not compare")
		}
	})
	t.Run("every live master", func(t *testing.T) {
		// Compared with one master of two live: not yet.
		an := newAPNet(t, 3, "a", "b", "c")
		a := an.m("a")
		if err := a.st.Admin().CreateSession(ctx, "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		a.rep.closeMasterRows()
		if err := a.rep.SyncGlobal(ctx, "b"); err != nil {
			t.Fatal(err)
		}
		if a.rep.masterRowsSynced.Load() {
			t.Fatal("an ordinary anti-entropy round with one master opened the rows")
		}
		an.mu.Lock()
		an.hung["c"] = true
		an.mu.Unlock()
		a.rep.closePool()
		if _, err := a.st.Admin().CheckSession(ctx, "s", time.Now()); !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("session compared with b, not c: %v, want unavailable", err)
		}
	})
	t.Run("claimants only", func(t *testing.T) {
		an := newGateNet(t)
		m := an.m("m")
		makeGrants(t, m)
		m.rep.masterRowsSynced.Store(false)
		if _, err := m.st.Admin().CheckSession(ctx, "real-session", time.Now()); err != nil {
			t.Fatalf("session with members that only say they are masters: %v", err)
		}
	})
}

// TestSyncKeepsToItsSpace: anti-entropy of one digest space takes no row,
// and compares no digest, of another's tables: a member answering a shard
// comparison with a session passes no master row for a shard one.
func TestSyncKeepsToItsSpace(t *testing.T) {
	ms := []store.Mutation{{Table: "sessions"}, {Table: "admin"}, {Table: "devices"}}
	for sp, want := range map[store.Space]string{store.SpaceShard: "devices", store.SpaceGlobal: "admin", store.SpaceMaster: "sessions"} {
		got := rowsIn(sp, slices.Clone(ms))
		if len(got) != 1 || got[0].Table != want {
			t.Errorf("rows in space %v: %v, want %s", sp, got, want)
		}
		ds := digestsIn(sp, []store.RowDigest{{RowRef: store.RowRef{Table: "sessions"}}, {RowRef: store.RowRef{Table: "admin"}}, {RowRef: store.RowRef{Table: "devices"}}})
		if len(ds) != 1 || ds[0].Table != want {
			t.Errorf("digests in space %v: %v, want %s", sp, ds, want)
		}
	}
}

// TestWithheldHintsBounded: the master rows kept for a member that does not
// prove the hub CA key are bounded; past maxStrikes answers without a proof
// none is kept for it, and its proof clears the count.
func TestWithheldHintsBounded(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	m := an.m("m")
	makeGrants(t, m)
	for range maxStrikes + 5 {
		m.rep.deliverHints(ctx)
	}
	n, _, err := m.hints.Usage(ctx, "s")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("hints for s after %d answers without a proof: %d, want none kept", maxStrikes+5, n)
	}
	m.rep.clearStrikes("s")
	if !m.rep.keepWithheld("s") {
		t.Fatal("rows for s not kept after its count was cleared")
	}
}

// TestWithheldHintsSizeBound: past maxWithheldHints hints for a member,
// withheld master rows are not kept for it.
func TestWithheldHintsSizeBound(t *testing.T) {
	an := newGateNet(t)
	m := an.m("m")
	for range maxWithheldHints {
		if err := m.hints.Add("s", []store.Mutation{{Table: "devices"}}); err != nil {
			t.Fatal(err)
		}
	}
	if m.rep.keepWithheld("s") {
		t.Fatal("withheld rows kept past the bound of hints")
	}
}

// TestRevokeWhatThisMasterLacks: a master revokes an MCP token, a
// dashboard token and a share link it never received (it was down when
// they were made, and the master that made them is down now): it keeps a
// revoked stub, and once the two meet the grant is revoked on both, in
// either order of delivery. The revocation says it reached one master of
// two; with both up, two of two.
func TestRevokeWhatThisMasterLacks(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 2, "a", "b")
	a, b := an.m("a"), an.m("b")
	now := time.Now()
	if err := a.st.Panels().Create(ctx, store.Panel{ID: "p", Name: "p", Widgets: "[]", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	an.setDown("b", true)
	if err := a.st.MCPTokens().Create(ctx, "mcp", "mcp-secret", "write", now); err != nil {
		t.Fatal(err)
	}
	if err := a.st.DashboardTokens().Create(ctx, store.DashboardToken{ID: "dash", Name: "dash", CreatedAt: now}, "dash-secret"); err != nil {
		t.Fatal(err)
	}
	if err := a.st.Panels().CreateLink(ctx, store.PanelLink{ID: "link", PanelID: "p", CreatedAt: now}, "link-secret"); err != nil {
		t.Fatal(err)
	}
	an.setDown("b", false)
	an.setDown("a", true)
	b.rep.masterRowsSynced.Store(true)
	revokes := map[string]func(context.Context) error{
		"mcp":  func(ctx context.Context) error { return b.st.MCPTokens().Revoke(ctx, "mcp", now) },
		"dash": func(ctx context.Context) error { return b.st.DashboardTokens().Revoke(ctx, "dash", now) },
		"link": func(ctx context.Context) error { return b.st.Panels().RevokeLink(ctx, "p", "link", now) },
	}
	for name, revoke := range revokes {
		rctx, reach := store.WithReach(ctx)
		if err := revoke(rctx); err != nil {
			t.Fatalf("b revokes %s it lacks: %v", name, err)
		}
		if *reach != (store.Reach{Applied: 1, Of: 2}) {
			t.Fatalf("reach of b's revocation of %s with a down: %+v, want 1 of 2", name, *reach)
		}
	}
	// A second revocation of a stub is of nothing in use.
	if err := b.st.MCPTokens().Revoke(ctx, "mcp", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke the stub again: %v, want not found", err)
	}
	an.setDown("a", false)
	// b's stubs reach a, a's grants reach b.
	b.rep.deliverHints(ctx)
	a.rep.deliverHints(ctx)
	for name, st := range map[string]*store.Store{"a": a.st, "b": b.st} {
		if _, err := st.MCPTokens().Check(ctx, "mcp-secret"); err == nil {
			t.Errorf("%s: the MCP token revoked on b is still valid", name)
		}
		if _, err := st.DashboardTokens().Check(ctx, "dash-secret", now); err == nil {
			t.Errorf("%s: the dashboard token revoked on b is still valid", name)
		}
		if _, _, err := st.Panels().CheckLink(ctx, "link-secret", now); err == nil {
			t.Errorf("%s: the link revoked on b is still valid", name)
		}
	}
	// Both up: the revocation reaches both masters.
	if err := a.st.MCPTokens().Create(ctx, "mcp2", "mcp2-secret", "write", now); err != nil {
		t.Fatal(err)
	}
	rctx, reach := store.WithReach(ctx)
	if err := a.st.MCPTokens().Revoke(rctx, "mcp2", now); err != nil {
		t.Fatal(err)
	}
	if *reach != (store.Reach{Applied: 2, Of: 2}) {
		t.Fatalf("reach with both masters up: %+v, want 2 of 2", *reach)
	}
}

// TestRevokeLinkOfAPanelThisMasterLacks: a master revokes a share link
// whose panel it lacks too (both made while it was down, and the master
// that made them is down now) (#389). It writes a stub of the panel with
// the link's: no list or check shows the stub, no command takes it for a
// panel, collecting tombstones keeps it, and once the two masters meet, in
// either order of delivery, the real panel is back on both and its link is
// revoked on both.
func TestRevokeLinkOfAPanelThisMasterLacks(t *testing.T) {
	for _, order := range []string{"stubs first", "grants first"} {
		t.Run(order, func(t *testing.T) {
			ctx := t.Context()
			an := newAPNet(t, 2, "a", "b")
			a, b := an.m("a"), an.m("b")
			now := time.Now()
			an.setDown("b", true)
			if err := a.st.Panels().Create(ctx, store.Panel{ID: "p", Name: "Hall", Widgets: "[]", CreatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := a.st.Panels().CreateLink(ctx, store.PanelLink{ID: "link", PanelID: "p", CreatedAt: now}, "link-secret"); err != nil {
				t.Fatal(err)
			}
			an.setDown("b", false)
			an.setDown("a", true)
			b.rep.masterRowsSynced.Store(true)

			rctx, reach := store.WithReach(ctx)
			if err := b.st.Panels().RevokeLink(rctx, "p", "link", now); err != nil {
				t.Fatalf("b revokes a link of a panel it lacks: %v", err)
			}
			if *reach != (store.Reach{Applied: 1, Of: 2}) {
				t.Fatalf("reach with a down: %+v, want 1 of 2", *reach)
			}
			// The stub is no panel.
			if ps, err := b.st.Panels().List(ctx); err != nil || len(ps) != 0 {
				t.Fatalf("b lists %+v, %v; want no panel", ps, err)
			}
			if _, err := b.st.Panels().Get(ctx, "p"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("b gets the stub: %v, want not found", err)
			}
			if _, _, err := b.st.Panels().CheckLink(ctx, "link-secret", now); err == nil {
				t.Fatal("b: the revoked link is valid")
			}
			if err := b.st.Panels().Update(ctx, store.Panel{ID: "p", Name: "x", Widgets: "[]"}, now); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("b updates the stub: %v, want not found", err)
			}
			if err := b.st.Panels().CreateLink(ctx, store.PanelLink{ID: "l2", PanelID: "p", CreatedAt: now}, "l2-secret"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("b links the stub: %v, want not found", err)
			}
			if err := b.st.Panels().Delete(ctx, "p"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("b deletes the stub: %v, want not found", err)
			}
			// A second revocation is of nothing in use.
			if err := b.st.Panels().RevokeLink(ctx, "p", "link", now); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("revoke the stub again: %v, want not found", err)
			}
			// The stub is no tombstone: collecting them keeps it, and the
			// link's stub with it.
			if _, err := b.st.GCTombstones(ctx, now.Add(2*store.TombstoneTTL)); err != nil {
				t.Fatal(err)
			}

			an.setDown("a", false)
			if order == "stubs first" {
				b.rep.deliverHints(ctx)
				a.rep.deliverHints(ctx)
			} else {
				a.rep.deliverHints(ctx)
				b.rep.deliverHints(ctx)
			}
			for name, st := range map[string]*store.Store{"a": a.st, "b": b.st} {
				if _, _, err := st.Panels().CheckLink(ctx, "link-secret", now); err == nil {
					t.Errorf("%s: the link revoked on b is still valid", name)
				}
				links, err := st.Panels().Links(ctx)
				if err != nil || len(links) != 1 || links[0].PanelID != "p" || links[0].RevokedAt.IsZero() {
					t.Errorf("%s: links %+v, %v; want link of p, revoked", name, links, err)
				}
				ps, err := st.Panels().List(ctx)
				if err != nil || len(ps) != 1 || ps[0].Name != "Hall" || ps[0].Widgets != "[]" {
					t.Errorf("%s: panels %+v, %v; want the real one", name, ps, err)
				}
			}
		})
	}
}

// TestRevocationWaitsForAMaster: a revocation tries a master that does not
// answer at once again for a few seconds, and counts it once it took it.
func TestRevocationWaitsForAMaster(t *testing.T) {
	ctx := t.Context()
	an := newAPNetWith(t, 2, func(c *ReplicatorConfig) { c.QuickTimeout = 200 * time.Millisecond }, "a", "b")
	a := an.m("a")
	now := time.Now()
	if err := a.st.MCPTokens().Create(ctx, "mcp", "mcp-secret", "write", now); err != nil {
		t.Fatal(err)
	}
	an.mu.Lock()
	an.hung["b"] = true
	an.mu.Unlock()
	a.rep.closePool()
	go func() {
		time.Sleep(time.Second)
		an.mu.Lock()
		an.hung["b"] = false
		an.mu.Unlock()
	}()
	rctx, reach := store.WithReach(ctx)
	if err := a.st.MCPTokens().Revoke(rctx, "mcp", now); err != nil {
		t.Fatal(err)
	}
	if *reach != (store.Reach{Applied: 2, Of: 2}) {
		t.Fatalf("reach once b answers within the wait: %+v, want 2 of 2", *reach)
	}
	if _, err := an.m("b").st.MCPTokens().Check(ctx, "mcp-secret"); err == nil {
		t.Fatal("b: the revoked token is still valid")
	}
}
