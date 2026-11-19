// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// nextSchema is the schema of the "newer binary" these tests run: this
// binary plus testMigration.
var nextSchema = store.SchemaVersion() + 1

// testMigration stands in for the migration a newer release adds. Its
// trigger makes an existing command (UpsertDevice) write the new table, so
// replicated writes exercise the new schema once the cluster migrated.
const testMigration = `
CREATE TABLE rolling_test (device_id TEXT PRIMARY KEY) STRICT;
CREATE TRIGGER rolling_test_insert AFTER INSERT ON devices
BEGIN
	INSERT INTO rolling_test (device_id) VALUES (NEW.id);
END;`

// migHub is a cluster node that serves its ClusterService on loopback and
// records that URL as its agent URL, as a hub does.
type migHub struct {
	*testNode
	srv   *httptest.Server
	newer bool
}

// migCluster is a 3-hub cluster whose hubs restart with another binary.
type migCluster struct {
	t  *testing.T
	ca *pki.CA
	// mu guards hubs; a writer holds it shared while it writes through one.
	mu   sync.RWMutex
	hubs []*migHub
}

func startMigHub(t *testing.T, ca *pki.CA, id, dir, addr string, bootstrap, newer bool) *migHub {
	t.Helper()
	var opts []store.Option
	if newer {
		opts = append(opts, store.WithExtraMigration(nextSchema, testMigration))
	}
	n := startNodeStore(t, ca, id, dir, addr, bootstrap, (*Node).BindForwarding, opts,
		func(c *Config) { c.ForwardWait = 5 * time.Second })
	return &migHub{testNode: n, srv: joinServer(t, n, ca), newer: newer}
}

// startMigCluster forms a 3-voter cluster; newer says which hubs run the
// newer binary.
func startMigCluster(t *testing.T, newer [3]bool) *migCluster {
	t.Helper()
	c := &migCluster{t: t, ca: newTestCA(t)}
	h1 := startMigHub(t, c.ca, "n1", "", "", true, newer[0])
	leaderOf(t, h1.testNode)
	h2 := startMigHub(t, c.ca, "n2", "", "", false, newer[1])
	h3 := startMigHub(t, c.ca, "n3", "", "", false, newer[2])
	addVoter(t, h1.testNode, h2.testNode)
	addVoter(t, h1.testNode, h3.testNode)
	waitReady(t, h2.testNode, h3.testNode)
	c.hubs = []*migHub{h1, h2, h3}
	for _, h := range c.hubs {
		c.announce(h)
	}
	return c
}

// announce records h's ClusterService URL in the cluster, through h.
func (c *migCluster) announce(h *migHub) {
	c.t.Helper()
	eventually(c.t, h.ID()+"'s URL recorded", func() bool {
		ctx, cancel := context.WithTimeout(c.t.Context(), 5*time.Second)
		defer cancel()
		return h.st.Hubs().SetAgentURL(ctx, h.ID(), h.srv.URL) == nil
	})
}

func (c *migCluster) nodes() []*testNode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*testNode
	for _, h := range c.hubs {
		out = append(out, h.testNode)
	}
	return out
}

func (c *migCluster) byID(id string) *migHub {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, h := range c.hubs {
		if h.ID() == id {
			return h
		}
	}
	return nil
}

func (c *migCluster) leader() *migHub {
	c.t.Helper()
	return c.byID(leaderOf(c.t, c.nodes()...).ID())
}

func (c *migCluster) followers() []*migHub {
	l := c.leader()
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*migHub
	for _, h := range c.hubs {
		if h != l {
			out = append(out, h)
		}
	}
	return out
}

// restart stops hub id and starts it again on the same data dir and Raft
// address with the newer binary or the original one, and waits until it has
// caught up.
func (c *migCluster) restart(id string, newer bool) *migHub {
	c.t.Helper()
	c.mu.Lock()
	i := slices.IndexFunc(c.hubs, func(h *migHub) bool { return h.ID() == id })
	old := c.hubs[i]
	dir, addr := old.dir, old.Addr()
	old.srv.Close()
	old.stop()
	c.mu.Unlock()

	h := startMigHub(c.t, c.ca, id, dir, addr, false, newer)
	waitReady(c.t, h.testNode)
	c.announce(h)
	c.mu.Lock()
	c.hubs[i] = h
	c.mu.Unlock()
	return h
}

// writer keeps writing devices through the cluster's hubs, round robin, and
// retries each write for up to writeBudget: a write that still fails then
// means the cluster stopped taking writes.
type writer struct {
	stop    context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	written []string
	failed  []error
}

const writeBudget = 10 * time.Second

func (c *migCluster) startWriter() *writer {
	ctx, cancel := context.WithCancel(context.Background())
	w := &writer{stop: cancel, done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for i := 0; ctx.Err() == nil; i++ {
			id := fmt.Sprintf("w%04d", i)
			if err := c.write(ctx, i, id); err != nil {
				if ctx.Err() != nil {
					return
				}
				w.mu.Lock()
				w.failed = append(w.failed, fmt.Errorf("write %s: %w", id, err))
				w.mu.Unlock()
			} else {
				w.mu.Lock()
				w.written = append(w.written, id)
				w.mu.Unlock()
			}
			select {
			case <-ctx.Done():
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	c.t.Cleanup(w.halt)
	return w
}

func (c *migCluster) write(ctx context.Context, i int, id string) error {
	deadline := time.Now().Add(writeBudget)
	for k := 0; ; k++ {
		c.mu.RLock()
		h := c.hubs[(i+k)%len(c.hubs)]
		var err error
		if !h.down {
			now := time.Now()
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = h.st.Devices().Upsert(wctx, store.Device{ID: id, Name: id, FirstSeen: now, LastSeen: now})
			cancel()
		} else {
			err = errors.New(h.ID() + " is down")
		}
		c.mu.RUnlock()
		if err == nil || ctx.Err() != nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// count returns how many writes succeeded so far.
func (w *writer) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.written)
}

// progress waits until a few more writes succeeded.
func (w *writer) progress(t *testing.T, what string) {
	t.Helper()
	n := w.count()
	eventually(t, "writes "+what, func() bool { return w.count() >= n+3 })
}

func (w *writer) halt() {
	w.stop()
	<-w.done
}

// rollingRows reads the device IDs in testMigration's table on h, or nil
// when the table does not exist there.
func rollingRows(t *testing.T, h *testNode) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(h.dir, "hearth.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(t.Context(), `SELECT device_id FROM rolling_test ORDER BY device_id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func schemaOf(t *testing.T, h *testNode) SchemaInfo {
	t.Helper()
	si, err := h.LocalSchema(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return si
}

// TestRollingUpgradeWithMigration (#25, done when 1): a 3-hub cluster moves
// to a binary with one more migration without downtime. Followers restart
// with the new binary one at a time and keep running the old schema; then
// leadership moves, the old leader restarts with the new binary, and the
// migrate command moves every hub to the new schema in log order. Writes
// keep working throughout.
func TestRollingUpgradeWithMigration(t *testing.T) {
	c := startMigCluster(t, [3]bool{})
	ctx := t.Context()
	w := c.startWriter()
	w.progress(t, "before the upgrade")

	// 1. Followers one at a time: the new binary runs the old schema.
	oldLeader := c.leader().ID()
	for _, f := range c.followers() {
		h := c.restart(f.ID(), true)
		if got := schemaOf(t, h.testNode); got != (SchemaInfo{Current: store.SchemaVersion(), Max: nextSchema}) {
			t.Fatalf("%s after its upgrade: schema %+v", h.ID(), got)
		}
		w.progress(t, "after upgrading "+h.ID())
	}

	// The old leader's binary blocks the migration, by name.
	_, err := c.followers()[0].MigrateSchema(ctx, nextSchema)
	want := fmt.Sprintf("%s (supports up to %d)", oldLeader, store.SchemaVersion())
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("migrate with an old leader: err = %v, want it to name %s", err, want)
	}

	// 2. Leadership moves to an upgraded hub; 3. the old leader upgrades.
	if err := c.byID(oldLeader).TransferLeadership(ctx, ""); err != nil {
		t.Fatalf("transfer leadership: %v", err)
	}
	if l := c.leader().ID(); l == oldLeader {
		t.Fatalf("%s still leads after the transfer", l)
	}
	w.progress(t, "after the leadership transfer")
	c.restart(oldLeader, true)
	w.progress(t, "after upgrading the old leader")

	// 4. Migrate, through a follower's control socket (forwarded).
	cc := serveControl(t, c.followers()[0].testNode)
	st, err := cc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range st.Peers {
		if p.Schema == nil || *p.Schema != (SchemaInfo{Current: store.SchemaVersion(), Max: nextSchema}) {
			t.Fatalf("status before the migrate: %s schema %+v (%s)", p.ID, p.Schema, p.SchemaError)
		}
	}
	from, err := cc.MigrateSchema(ctx, nextSchema)
	if err != nil || from != store.SchemaVersion() {
		t.Fatalf("migrate = %d, %v", from, err)
	}
	w.progress(t, "after the migrate")
	w.halt()
	if len(w.failed) > 0 {
		t.Fatalf("writes failed for %v during the upgrade: %v", writeBudget, w.failed)
	}
	t.Logf("%d writes during the rolling upgrade", len(w.written))

	// Every hub is at the new schema, and a replicated write uses it.
	for _, h := range c.hubs {
		eventually(t, h.ID()+" at the new schema", func() bool {
			si, err := h.LocalSchema(ctx)
			return err == nil && si.Current == nextSchema
		})
	}
	upsert(t, c.leader().testNode, "after-migrate")
	for _, h := range c.hubs {
		eventually(t, "the new table used on "+h.ID(), func() bool {
			return slices.Contains(rollingRows(t, h.testNode), "after-migrate")
		})
		for _, id := range w.written {
			if !hasDevice(h.testNode, id) {
				t.Fatalf("write %s missing on %s", id, h.ID())
			}
		}
	}
	// Migrating again is refused: the cluster is there already.
	if _, err := c.leader().MigrateSchema(ctx, nextSchema); !errors.Is(err, store.ErrSchemaNotNewer) {
		t.Fatalf("second migrate: err = %v, want ErrSchemaNotNewer", err)
	}

	// A restarted hub restores its older snapshot and replays the migrate
	// from the log: the same tables as the others.
	f := c.followers()[0]
	want2 := rollingRows(t, c.leader().testNode)
	f = c.restart(f.ID(), true)
	if got := rollingRows(t, f.testNode); !slices.Equal(got, want2) || schemaOf(t, f.testNode).Current != nextSchema {
		t.Fatalf("%s after replay: rows %v, schema %+v; want rows %v", f.ID(), got, schemaOf(t, f.testNode), want2)
	}

	// The old binary refuses the migrated database.
	f.srv.Close()
	f.stop()
	_, err = store.Open(ctx, filepath.Join(f.dir, "hearth.db"), store.WithoutUpgrade())
	if !errors.Is(err, store.ErrSchemaMismatch) {
		t.Fatalf("old binary on the migrated database: err = %v, want ErrSchemaMismatch", err)
	}
}

// TestMigrateNeedsEveryHub (#25, done when 2): a hub whose binary does not
// support the target schema, or that cannot be asked, blocks the migration
// with an error naming it, and nothing is proposed.
func TestMigrateNeedsEveryHub(t *testing.T) {
	// n1 runs the old binary; n2 and n3 the newer one, restored from n1's
	// older snapshot when they joined.
	c := startMigCluster(t, [3]bool{false, true, true})
	ctx := t.Context()
	n1, n2 := c.byID("n1"), c.byID("n2")
	if l := c.leader(); l != n1 {
		t.Fatalf("leader %s, want n1, which formed the cluster", l.ID())
	}
	if got := schemaOf(t, n2.testNode); got != (SchemaInfo{Current: store.SchemaVersion(), Max: nextSchema}) {
		t.Fatalf("newer joiner: schema %+v", got)
	}

	_, err := c.leader().MigrateSchema(ctx, nextSchema)
	want := fmt.Sprintf("n1 (supports up to %d)", store.SchemaVersion())
	if !errors.Is(err, ErrSchemaUnsupported) || !strings.Contains(err.Error(), want) {
		t.Fatalf("migrate on the leader: err = %v, want ErrSchemaUnsupported naming %s", err, want)
	}
	if strings.Contains(err.Error(), "n2") || strings.Contains(err.Error(), "n3") {
		t.Errorf("refusal names hubs that support the schema: %v", err)
	}
	// Forwarded from a follower, the leader's refusal comes back as it is.
	if _, err := n2.MigrateSchema(ctx, nextSchema); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("migrate on a follower: err = %v, want it to name %s", err, want)
	}
	// Not newer than the cluster's schema.
	if _, err := n2.MigrateSchema(ctx, store.SchemaVersion()); err == nil ||
		!strings.Contains(err.Error(), store.ErrSchemaNotNewer.Error()) {
		t.Fatalf("migrate to the current schema: err = %v", err)
	}
	// The support check cannot be bypassed through the generic write paths.
	for _, h := range []*migHub{n1, n2} {
		if _, err := h.ApplyOrForward(ctx, store.MigrateSchema{To: nextSchema}); !errors.Is(err, errMigrateViaLog) {
			t.Fatalf("MigrateSchema through ApplyOrForward on %s: err = %v", h.ID(), err)
		}
	}

	// A hub that cannot be asked blocks it too. (The leader reads its own
	// schema locally, so the unreachable one is a follower.)
	c.restart("n1", true)
	gone := c.followers()[0]
	gone.srv.Close()
	_, err = c.leader().MigrateSchema(ctx, nextSchema)
	if !errors.Is(err, ErrSchemaUnsupported) || !strings.Contains(err.Error(), gone.ID()+" (cannot read its schema") {
		t.Fatalf("migrate with %s unreachable: err = %v", gone.ID(), err)
	}
	for _, h := range c.hubs {
		if v := schemaOf(t, h.testNode).Current; v != store.SchemaVersion() {
			t.Fatalf("%s at schema %d after refused migrations", h.ID(), v)
		}
	}
}

// TestJoinWithNewerBinary: a hub whose binary is newer than the cluster's
// schema joins, restores the cluster's older snapshot and runs at that
// schema. (An older binary is refused: TestJoinRejects.)
func TestJoinWithNewerBinary(t *testing.T) {
	ca := newTestCA(t)
	n1 := startNode(t, ca, "n1", "", "", true)
	leaderOf(t, n1)
	upsert(t, n1, "pi")
	srv := joinServer(t, n1, ca)
	dir, ln := t.TempDir(), heldAddr(t)
	addr := ln.Addr().String()
	if err := Join(t.Context(), JoinParams{
		URL: srv.URL, Token: joinToken(t, n1, ca, time.Now().Add(time.Hour)), DataDir: dir,
		NodeID: "n2", RaftAddress: addr, MaxSchema: nextSchema,
	}); err != nil {
		t.Fatalf("join with a newer binary: %v", err)
	}
	jca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := startNodeStore(t, jca, "n2", dir, addr, false, (*Node).Bind,
		[]store.Option{store.WithExtraMigration(nextSchema, testMigration)}, withListener(ln))
	waitReady(t, h)
	if err := Promote(t.Context(), dir, "n2"); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if !hasDevice(h, "pi") {
		t.Fatal("joiner missing the cluster's data")
	}
	if got := schemaOf(t, h); got != (SchemaInfo{Current: store.SchemaVersion(), Max: nextSchema}) {
		t.Fatalf("joiner schema %+v", got)
	}
	if rollingRows(t, h) != nil {
		t.Fatal("joiner has the newer schema's table before the cluster migrated")
	}
}

// hubCertsSchema is the schema whose migration (00006) added hub_certs, the
// first one past what v0.0.1-rc.3 shipped.
const hubCertsSchema = 6

// schema5Dir returns a data dir whose database is at schema 5, as a cluster
// formed by v0.0.1-rc.3 left it: before hub_certs. It runs migration
// 00006's down step by hand.
func schema5Dir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hearth.db")
	st, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(t.Context(), `DROP TABLE hub_certs;
		DELETE FROM goose_db_version WHERE version_id >= 6`); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRollingUpgradeFromSchema5 (#95): every hub runs this binary, but the
// cluster's database is still at schema 5, before hub_certs, as after
// replacing rc.3 binaries one at a time. Hub-to-hub RPCs (Forward,
// SchemaInfo) work, a removal is refused with a clear error without halting
// any hub, and `hearth cluster migrate` moves the cluster to 6, after which
// each hub records its node certificate.
func TestRollingUpgradeFromSchema5(t *testing.T) {
	if store.SchemaVersion() < hubCertsSchema {
		t.Fatalf("binary at schema %d", store.SchemaVersion())
	}
	ctx := t.Context()
	c := &migCluster{t: t, ca: newTestCA(t)}
	h1 := startMigHub(t, c.ca, "n1", schema5Dir(t), "", true, false)
	leaderOf(t, h1.testNode)
	h2 := startMigHub(t, c.ca, "n2", schema5Dir(t), "", false, false)
	h3 := startMigHub(t, c.ca, "n3", schema5Dir(t), "", false, false)
	addVoter(t, h1.testNode, h2.testNode)
	addVoter(t, h1.testNode, h3.testNode)
	waitReady(t, h2.testNode, h3.testNode)
	c.hubs = []*migHub{h1, h2, h3}
	at5 := SchemaInfo{Current: hubCertsSchema - 1, Max: store.SchemaVersion()}
	for _, h := range c.hubs {
		if got := schemaOf(t, h.testNode); got != at5 {
			t.Fatalf("%s: schema %+v, want %+v", h.ID(), got, at5)
		}
		c.announce(h) // forwarded to the leader from a follower
	}

	// Each hub waits to record its node certificate until the migrate.
	var wg sync.WaitGroup
	recCtx, stopRec := context.WithCancel(ctx)
	t.Cleanup(func() { stopRec(); wg.Wait() })
	for _, h := range c.hubs {
		wg.Go(func() { h.RecordNodeCert(recCtx) })
	}

	w := c.startWriter()
	w.progress(t, "on schema 5")

	// Removing a hub needs hub_certs: refused, with the way out, and the
	// hub stays a member. Through a follower, forwarded to the leader.
	f := c.followers()
	cc := serveControl(t, f[0].testNode)
	if _, err := cc.RemoveMember(ctx, f[1].ID()); err == nil || !strings.Contains(err.Error(), "hearth cluster migrate") {
		t.Fatalf("remove on schema 5: err = %v, want it to say to migrate first", err)
	}
	if got := voters(t, c.leader().testNode); len(got) != 3 {
		t.Fatalf("voters after the refused removal = %v", got)
	}
	// A revoke that reaches the log is refused on every node alike: no
	// state machine halts.
	if _, err := f[0].st.Hubs().RevokeCerts(ctx, f[1].ID(), time.Now()); err == nil ||
		!strings.Contains(err.Error(), "hearth cluster migrate") {
		t.Fatalf("revoke on schema 5: err = %v, want it to say to migrate first", err)
	}
	for _, h := range c.hubs {
		if err := h.fsm.haltedErr(); err != nil {
			t.Fatalf("%s halted: %v", h.ID(), err)
		}
		if certs, err := h.st.Hubs().Certs(ctx, h.ID()); err != nil || len(certs) != 0 {
			t.Fatalf("%s certs on schema 5 = %v, %v", h.ID(), certs, err)
		}
	}
	w.progress(t, "after the refused removal")

	// Every hub's schema is readable, and the migrate goes through.
	st, err := cc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range st.Peers {
		if p.Schema == nil || *p.Schema != at5 {
			t.Fatalf("status before the migrate: %s schema %+v (%s)", p.ID, p.Schema, p.SchemaError)
		}
	}
	from, err := cc.MigrateSchema(ctx, hubCertsSchema)
	if err != nil || from != hubCertsSchema-1 {
		t.Fatalf("migrate = %d, %v", from, err)
	}
	w.progress(t, "after the migrate")
	w.halt()
	if len(w.failed) > 0 {
		t.Fatalf("writes failed for %v on schema 5: %v", writeBudget, w.failed)
	}

	// Each hub's certificate gets recorded, on every hub.
	for _, h := range c.hubs {
		eventually(t, h.ID()+" at schema 6", func() bool { return schemaOf(t, h.testNode).Current == hubCertsSchema })
		for _, o := range c.hubs {
			eventually(t, o.ID()+"'s certificate recorded on "+h.ID(), func() bool {
				certs, err := h.st.Hubs().Certs(ctx, o.ID())
				return err == nil && len(certs) == 1 && certs[0].Serial == pki.SerialString(o.cert)
			})
		}
	}
	for _, h := range c.hubs {
		if err := h.fsm.haltedErr(); err != nil {
			t.Fatalf("%s halted: %v", h.ID(), err)
		}
	}
}

// schemaBeforePinsDir is a data dir whose database is at the schema before
// certificate fingerprints (store.CertPinsSchema - 1).
func schemaBeforePinsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hearth.db")
	st, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(t.Context(), fmt.Sprintf(`ALTER TABLE hub_certs DROP COLUMN ca_fp;
		ALTER TABLE hub_certs DROP COLUMN fingerprint;
		ALTER TABLE certs DROP COLUMN pin_mismatch_at;
		ALTER TABLE certs DROP COLUMN ca_fp;
		ALTER TABLE certs DROP COLUMN fingerprint;
		DELETE FROM goose_db_version WHERE version_id >= %d`, store.CertPinsSchema)); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A hub whose certificate was recorded before fingerprints were gets its
// fingerprint filled in by a live migrate, with no restart: RecordNodeCert
// keeps waiting for the schema.
func TestNodeCertFingerprintAfterLiveMigrate(t *testing.T) {
	ctx := t.Context()
	h := startMigHub(t, newTestCA(t), "n1", schemaBeforePinsDir(t), "", true, false)
	leaderOf(t, h.testNode)
	recCtx, stopRec := context.WithCancel(ctx)
	var wg sync.WaitGroup
	t.Cleanup(func() { stopRec(); wg.Wait() })
	wg.Go(func() { h.RecordNodeCert(recCtx) })
	eventually(t, "the certificate recorded without a fingerprint", func() bool {
		certs, err := h.st.Hubs().Certs(ctx, h.ID())
		return err == nil && len(certs) == 1 && certs[0].Fingerprint == ""
	})
	if _, err := h.MigrateSchema(ctx, store.CertPinsSchema); err != nil {
		t.Fatalf("migrate to %d: %v", store.CertPinsSchema, err)
	}
	eventually(t, "the fingerprint recorded after the migrate", func() bool {
		certs, err := h.st.Hubs().Certs(ctx, h.ID())
		return err == nil && len(certs) == 1 && certs[0].Fingerprint == pki.FingerprintHex(h.cert) &&
			certs[0].CAFP != ""
	})
}

// TestJoinOnSchema5 (#95): a hub joins a cluster still at schema 5, before
// hub_certs. The leader cannot record the joiner's certificate yet; the
// join, and the promotion over the joiner's hub certificate, still work.
func TestJoinOnSchema5(t *testing.T) {
	ca := newTestCA(t)
	n1 := startNode(t, ca, "n1", schema5Dir(t), "", true)
	leaderOf(t, n1)
	srv := joinServer(t, n1, ca)
	n2 := joinAndStart(t, srv.URL, joinToken(t, n1, ca, time.Now().Add(time.Hour)), "n2")
	if got := voters(t, n1); len(got) != 2 {
		t.Fatalf("voters = %v", got)
	}
	if v := schemaOf(t, n2).Current; v != hubCertsSchema-1 {
		t.Fatalf("joiner at schema %d", v)
	}
	if err := n2.st.Hubs().CheckCert(t.Context(), pki.SerialString(n2.cert)); err != nil {
		t.Fatalf("CheckCert on schema 5 = %v", err)
	}
}
