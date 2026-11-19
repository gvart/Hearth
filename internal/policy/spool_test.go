// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite" // to count raw audit rows

	"github.com/gvart/hearth/internal/store"
)

// switchedAudit is a store's audit log that fails every append while down,
// as a cluster without quorum does.
type switchedAudit struct {
	store.Audit
	down atomic.Bool
}

var errNoQuorum = errors.New("no quorum")

func (a *switchedAudit) Append(ctx context.Context, e store.AuditEntry) (int64, error) {
	if a.down.Load() {
		return 0, errNoQuorum
	}
	return a.Audit.Append(ctx, e)
}

type spoolFixture struct {
	st    *store.Store
	db    *sql.DB
	audit *switchedAudit
	dir   string
	sp    *Spool
}

func newSpoolFixture(t *testing.T) *spoolFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hearth.db")
	st, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &spoolFixture{st: st, db: db, audit: &switchedAudit{Audit: st.Audit()}, dir: filepath.Join(t.TempDir(), "spool")}
	f.sp = newTestSpool(t, f.dir, f.audit)
	return f
}

func newTestSpool(t *testing.T, dir string, audit Auditor) *Spool {
	t.Helper()
	sp, err := OpenSpool(dir, audit, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	sp.retryMin, sp.retryMax, sp.timeout = 10*time.Millisecond, 50*time.Millisecond, time.Second
	return sp
}

// rows counts the audit rows of action, outcome entries included: Query
// folds those into their start and would hide a duplicate.
func (f *spoolFixture) rows(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *spoolFixture) files(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(f.dir, pattern))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var spoolReq = Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi"}

// TestSpooledOutcomeLandsOnce: an outcome that cannot be written is spooled,
// the action reports its own result, and the drain writes the entry once,
// with the time it was made, even when the first write landed after all.
func TestSpooledOutcomeLandsOnce(t *testing.T) {
	ctx := t.Context()
	f := newSpoolFixture(t)
	e := New(f.audit)
	e.SpoolTo(f.sp)
	made := time.UnixMilli(1_700_000_000_000)
	e.now = func() time.Time { return made }

	err := e.Do(ctx, spoolReq, func(context.Context) error { f.audit.down.Store(true); return nil })
	if err != nil {
		t.Fatalf("Do = %v, want nil: the outcome is spooled, not lost", err)
	}
	files := f.files(t, "*"+spoolExt)
	if len(files) != 1 {
		t.Fatalf("spool holds %v, want one entry", files)
	}
	if info, err := os.Stat(files[0]); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("spool file = %v, %v; want mode 0600", info, err)
	}
	if !f.sp.Drain(ctx) {
		t.Error("Drain without the log reported nothing left")
	}

	// The first write committed after all, as a Raft apply that timed out
	// may: the spooled copy must not add a second outcome.
	root, err := os.OpenRoot(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	en, err := readSpooled(root, filepath.Base(files[0]))
	_ = root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Audit().Append(ctx, en); err != nil {
		t.Fatal(err)
	}

	f.audit.down.Store(false)
	if f.sp.Drain(ctx) {
		t.Error("Drain with the log back left entries")
	}
	if left := f.files(t, "*"); len(left) != 0 {
		t.Errorf("spool left %v", left)
	}
	if n := f.rows(t, string(DeviceRevoke)); n != 2 {
		t.Errorf("%d rows, want exactly 2 (started and one outcome)", n)
	}
	entries, err := f.st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(DeviceRevoke)}}, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	if entries[0].Result != "ok" || !entries[0].TS.Equal(made) {
		t.Errorf("entry = %+v, want the outcome ok at %v", entries[0], made)
	}
}

// TestEntryBeforeTheActionIsNeverSpooled: the entry an action waits for is
// not spooled: the action is refused, and nothing lands later to claim it ran.
func TestEntryBeforeTheActionIsNeverSpooled(t *testing.T) {
	f := newSpoolFixture(t)
	e := New(f.audit)
	e.SpoolTo(f.sp)
	f.audit.down.Store(true)
	ran := false
	if err := e.Do(t.Context(), spoolReq, func(context.Context) error { ran = true; return nil }); err == nil || ran {
		t.Fatalf("Do = %v, ran %v; want refused", err, ran)
	}
	if got := f.files(t, "*"); len(got) != 0 {
		t.Errorf("spool holds %v, want nothing", got)
	}
}

// TestOutcomeNotRecordedWhenTheSpoolFails: an outcome neither written nor
// spooled is still reported as not recorded.
func TestOutcomeNotRecordedWhenTheSpoolFails(t *testing.T) {
	f := newSpoolFixture(t)
	e := New(f.audit)
	e.SpoolTo(f.sp)
	if err := os.RemoveAll(f.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.dir, nil, 0o600); err != nil { // a file where the spool's dir was
		t.Fatal(err)
	}
	err := e.Do(t.Context(), spoolReq, func(context.Context) error { f.audit.down.Store(true); return nil })
	if !errors.Is(err, ErrOutcomeNotRecorded) {
		t.Errorf("Do = %v, want ErrOutcomeNotRecorded", err)
	}
}

// TestHeldDenialIsSpooled: the entry closing a held request is spooled too.
func TestHeldDenialIsSpooled(t *testing.T) {
	f := newSpoolFixture(t)
	e := NewWithConfig(f.audit, f.st.Approvals(), Config{Classes: map[Class]Mode{Dangerous: ModeConfirm}})
	e.SpoolTo(f.sp)
	e.poll = time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	e.OnHeld(func(context.Context, store.Approval) { f.audit.down.Store(true); cancel() })
	if err := e.Do(ctx, spoolReq, func(context.Context) error { return nil }); !errors.Is(err, ErrDenied) {
		t.Fatalf("Do = %v, want a denial", err)
	}
	if got := f.files(t, "*"+spoolExt); len(got) != 1 {
		t.Fatalf("spool holds %v, want the denial", got)
	}
	f.audit.down.Store(false)
	if f.sp.Drain(t.Context()) {
		t.Fatal("Drain left entries")
	}
	if n := f.rows(t, string(DeviceRevoke)); n != 2 {
		t.Errorf("%d rows, want the hold and its denial", n)
	}
}

// TestSpoolCorruptEntryRecordsTheGap: an entry the spool cannot read back is
// replaced by a visible AuditEntryLost entry, once, and set aside.
func TestSpoolCorruptEntryRecordsTheGap(t *testing.T) {
	ctx := t.Context()
	cases := map[string]func(t *testing.T, path string){
		"corrupt": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"ts":`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"no action": func(t *testing.T, path string) {
			b := `{"ts":"2026-01-01T00:00:00Z","actor_kind":"a","actor_id":"b","decision":"allow","key":"k"}`
			if err := os.WriteFile(path, []byte(b), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"no key": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"ts":"2026-01-01T00:00:00Z","actor_kind":"a"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"too large": func(t *testing.T, path string) {
			big := make([]byte, maxSpooledEntry+1)
			for i := range big {
				big[i] = ' '
			}
			if err := os.WriteFile(path, big, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSpoolFixture(t)
			write(t, filepath.Join(f.dir, "00000000000000000001-k"+spoolExt))
			f.audit.down.Store(true)
			if !f.sp.Drain(ctx) {
				t.Error("Drain without the log reported nothing left")
			}
			f.audit.down.Store(false)
			for range 2 {
				if f.sp.Drain(ctx) {
					t.Error("Drain left entries")
				}
			}
			if n := f.rows(t, AuditEntryLost); n != 1 {
				t.Errorf("%d %s rows, want 1", n, AuditEntryLost)
			}
			lost, err := f.st.Audit().Query(ctx, store.AuditFilter{Actions: []string{AuditEntryLost}}, 10)
			if err != nil || len(lost) != 1 || lost[0].Decision != Deny {
				t.Errorf("gap entries = %+v, %v; want one with decision %s", lost, err, Deny)
			}
			if bad := f.files(t, "*"+spoolBad); len(bad) != 1 {
				t.Errorf("set aside %v, want the one file", bad)
			}
		})
	}
}

// TestSpoolUnreadableEntryIsRetried: a file that cannot be read now (here a
// permission error) is not taken for lost: it stays, holds up the queue, and
// is written once it can be read.
func TestSpoolUnreadableEntryIsRetried(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file modes do not stop this user reading")
	}
	ctx := t.Context()
	f := newSpoolFixture(t)
	if err := f.sp.Put(store.AuditEntry{
		TS: time.Now(), ActorKind: ActorHub, ActorID: "n1", Action: "x", Decision: Allow, Key: "k",
	}); err != nil {
		t.Fatal(err)
	}
	files := f.files(t, "*"+spoolExt)
	if len(files) != 1 {
		t.Fatalf("spool holds %v", files)
	}
	if err := os.Chmod(files[0], 0o000); err != nil {
		t.Fatal(err)
	}
	if !f.sp.Drain(ctx) {
		t.Error("Drain of an unreadable file reported nothing left")
	}
	if n, lost := f.rows(t, "x"), f.rows(t, AuditEntryLost); n != 0 || lost != 0 {
		t.Errorf("%d entries, %d gaps; want neither yet", n, lost)
	}
	if err := os.Chmod(files[0], 0o600); err != nil {
		t.Fatal(err)
	}
	if f.sp.Drain(ctx) {
		t.Error("Drain left entries")
	}
	if n, lost := f.rows(t, "x"), f.rows(t, AuditEntryLost); n != 1 || lost != 0 {
		t.Errorf("%d entries, %d gaps; want the entry once and no gap", n, lost)
	}
}

// TestOpenSpoolTidiesItsDir: an existing dir is made 0700, and what a cut
// short write left is removed; whole entries stay.
func TestOpenSpoolTidiesItsDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1-a" + spoolExt + spoolTmp, "2-b" + spoolExt} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newTestSpool(t, dir, nil)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", info.Mode().Perm())
	}
	left, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || filepath.Base(left[0]) != "2-b"+spoolExt {
		t.Errorf("dir holds %v, want only the whole entry", left)
	}
}

// failingCreate is an approval store that cannot store anything, as one
// without quorum.
type failingCreate struct{ autoApprovals }

func (*failingCreate) Create(context.Context, store.Approval) error { return errNoQuorum }

// TestUnheldDenialIsNotSpooled: a request that needed approval but could not
// be held wrote no pending entry, so its denial closes nothing: it is not
// spooled, and Do fails with the audit error as for a plain denial. Without
// quorum, repeating such requests must not grow the spool.
func TestUnheldDenialIsNotSpooled(t *testing.T) {
	for name, approvals := range map[string]Approvals{"no approvals": nil, "create fails": &failingCreate{}} {
		t.Run(name, func(t *testing.T) {
			f := newSpoolFixture(t)
			e := NewWithConfig(f.audit, approvals, Config{Classes: map[Class]Mode{Dangerous: ModeConfirm}})
			e.SpoolTo(f.sp)
			f.audit.down.Store(true)
			for range 3 {
				err := e.Do(t.Context(), spoolReq, func(context.Context) error { return nil })
				if !errors.Is(err, errNoQuorum) || errors.Is(err, ErrDenied) {
					t.Fatalf("Do = %v, want the audit error", err)
				}
			}
			if got := f.files(t, "*"); len(got) != 0 {
				t.Errorf("spool holds %v, want nothing", got)
			}
		})
	}
}

// TestSpoolAfterShutdown: an entry spooled once Run has stopped, or left
// when it stopped mid-retry, stays on disk, and the next spool on the same
// dir, after a restart, writes it.
func TestSpoolAfterShutdown(t *testing.T) {
	f := newSpoolFixture(t)
	f.audit.down.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.sp.Run(ctx) }()
	put := func(key string) {
		t.Helper()
		if err := f.sp.Put(store.AuditEntry{
			TS: time.Now(), ActorKind: ActorHub, ActorID: "n1", Action: "x", Decision: Allow, Key: key,
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("during")
	time.Sleep(30 * time.Millisecond) // a retry or two fail
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	put("after")
	f.audit.down.Store(false)
	if f.sp.Drain(ctx) != true {
		t.Error("Drain on a stopped context wrote entries")
	}
	if got := f.files(t, "*"+spoolExt); len(got) != 2 {
		t.Fatalf("spool holds %v, want both entries", got)
	}

	restarted := newTestSpool(t, f.dir, f.audit)
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	go func() { _ = restarted.Run(ctx2) }()
	deadline := time.Now().Add(5 * time.Second)
	for f.rows(t, "x") < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := f.rows(t, "x"); n != 2 {
		t.Errorf("%d rows after the restart, want 2", n)
	}
}

// TestRecordEndIsSpooled: the end of a session, such as a terminal's, that
// cannot be written while the log is down is spooled and lands once it is back.
func TestRecordEndIsSpooled(t *testing.T) {
	ctx := t.Context()
	f := newSpoolFixture(t)
	e := New(f.audit)
	e.SpoolTo(f.sp)
	req := Request{ActorKind: ActorWeb, ActorID: "10.0.0.1", Action: DeviceShell, Target: "pi"}

	f.audit.down.Store(true)
	if err := e.RecordEnd(ctx, req, "closed", map[string]any{"reason": "idle"}); err != nil {
		t.Fatalf("RecordEnd = %v, want nil: the entry is spooled, not lost", err)
	}
	if files := f.files(t, "*"+spoolExt); len(files) != 1 {
		t.Fatalf("spool holds %v, want one entry", files)
	}
	f.audit.down.Store(false)
	if f.sp.Drain(ctx) {
		t.Error("Drain with the log back left entries")
	}
	if n := f.rows(t, string(DeviceShell)); n != 1 {
		t.Errorf("%d rows, want the one end entry", n)
	}
}
