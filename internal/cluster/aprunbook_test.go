// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hlc"
	"github.com/gvart/hearth/internal/store"
)

// Runbook run saves in a sharded cluster (#292). A run's saves are decided
// by its version: a save from a version the run has moved past is refused,
// so a step is recorded as running once and never run twice. These tests
// hold that check to the newest copy of the run, whichever master saves it:
// runs live on the masters (#387), every member here. Hints and
// anti-entropy run hourly here, so a stale copy stays stale until the test
// delivers the hints.

// runbookPreferring returns a runbook id whose preference list starts with
// first.
func runbookPreferring(t *testing.T, ids []string, first ...string) string {
	t.Helper()
	ring := NewRing(ids)
	for i := range 100000 {
		k := "rb" + strconv.Itoa(i)
		if slices.Equal(ring.Preference(store.BucketOf(store.Token(k)))[:len(first)], first) {
			return k
		}
	}
	t.Fatalf("no runbook preferring %v", first)
	return ""
}

// createRun stores run id of runbook rb through m, at version 1.
func createRun(t *testing.T, m *apMember, id, rb string) store.RunbookRun {
	t.Helper()
	run := store.RunbookRun{
		ID: id, RunbookID: rb, Status: "running", StartedBy: "web/x", StartedAt: time.Now(),
		Source: []byte("sealed"), State: json.RawMessage(`{"step":0}`),
	}
	if err := m.st.RunbookRuns().Create(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	run.Version = 1
	return run
}

// saveRun saves run through m from version, with state step.
func saveRun(t *testing.T, m *apMember, run store.RunbookRun, version int64, step int) (int64, error) {
	t.Helper()
	run.Version, run.UpdatedAt = version, time.Now()
	run.State = json.RawMessage(fmt.Sprintf(`{"step":%d}`, step))
	return m.st.RunbookRuns().Save(t.Context(), run)
}

// localRun reads run id's version and state from m's own database.
func localRun(t *testing.T, m *apMember, id string) (int64, string, bool) {
	t.Helper()
	rows, err := m.st.ReadLocal(t.Context(), `SELECT version, state FROM runbook_runs WHERE id = ?`, store.Values{id})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Vals) == 0 {
		return 0, "", false
	}
	v, _ := rows.Vals[0][0].(int64)
	s, _ := rows.Vals[0][1].(string)
	return v, s, true
}

// wantRunEverywhere checks that every member in ms reads run id at version
// with state.
func wantRunEverywhere(t *testing.T, an *apNet, ms []string, id string, version int64, state string) {
	t.Helper()
	for _, m := range ms {
		run, err := an.m(m).st.RunbookRuns().Get(t.Context(), id)
		if err != nil || run.Version != version || string(run.State) != state {
			t.Errorf("%s reads run at version %d, state %s, %v; want %d, %s", m, run.Version, run.State, err, version, state)
		}
	}
}

// A save decided on a master that missed the run's last saves decides on
// the newest copy: a save from the version it holds is refused, and one
// from the newest version is taken. No save is lost, and every master reads
// the run at its newest version. Three masters, so the saves a misses still
// reach a majority of them.
func TestRunbookSaveOnAStaleReplica(t *testing.T) {
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 3, ids...)
	run := createRun(t, an.m("b"), "run1", "rb1")
	apEventually(t, "a and c to hold the run", func() bool {
		_, _, onA := localRun(t, an.m("a"), "run1")
		_, _, onC := localRun(t, an.m("c"), "run1")
		return onA && onC
	})

	// a, the first master, on which saves are decided, misses two saves.
	an.setDown("a", true)
	v := int64(1)
	for step := 1; step <= 2; step++ {
		next, err := saveRun(t, an.m("c"), run, v, step)
		if err != nil {
			t.Fatalf("save of step %d with a down = %v", step, err)
		}
		v = next
	}
	an.setDown("a", false)
	if got, _, _ := localRun(t, an.m("a"), "run1"); got != 1 {
		t.Fatalf("a holds version %d; the test needs it stale at 1", got)
	}

	// A hub that read the run before those saves: refused, though a's copy
	// is at the version it read.
	if _, err := saveRun(t, an.m("a"), run, 1, 9); !errors.Is(err, store.ErrRunbookRunConflict) {
		t.Fatalf("save from version 1 on the stale a = %v, want ErrRunbookRunConflict", err)
	}
	// A hub that read the newest version: taken, though it is decided on a.
	if got, err := saveRun(t, an.m("b"), run, v, 3); err != nil || got != v+1 {
		t.Fatalf("save from version %d = %d, %v", v, got, err)
	}

	for _, id := range ids {
		an.m(id).rep.deliverHints(t.Context())
	}
	wantRunEverywhere(t, an, ids, "run1", 4, `{"step":3}`)
	for _, m := range ids {
		if got, state, _ := localRun(t, an.m(m), "run1"); got != 4 || state != `{"step":3}` {
			t.Errorf("%s holds version %d, %s; want 4, step 3", m, got, state)
		}
	}
}

// Two masters that are both replicas of a run save it from the same version
// at once: exactly one save is taken, the other is refused, and every copy
// ends at the save that was taken.
func TestRunbookConcurrentSavesFromOneVersion(t *testing.T) {
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	rb := runbookPreferring(t, ids, "b", "c", "a")
	run := createRun(t, an.m("a"), "run1", rb)
	apEventually(t, "b and c to hold the run", func() bool {
		_, _, onB := localRun(t, an.m("b"), "run1")
		_, _, onC := localRun(t, an.m("c"), "run1")
		return onB && onC
	})

	v := int64(1)
	for round := range 20 {
		var (
			wg   sync.WaitGroup
			errs [2]error
		)
		for i, m := range []string{"b", "c"} {
			wg.Go(func() { _, errs[i] = saveRun(t, an.m(m), run, v, 10*round+i) })
		}
		wg.Wait()
		taken := 0
		for i, err := range errs {
			switch {
			case err == nil:
				taken++
			case !errors.Is(err, store.ErrRunbookRunConflict):
				t.Fatalf("round %d: save %d = %v", round, i, err)
			}
		}
		if taken != 1 {
			t.Fatalf("round %d: %d saves from version %d taken (%v), want exactly 1", round, taken, v, errs)
		}
		v++
	}

	for _, id := range ids {
		an.m(id).rep.deliverHints(t.Context())
	}
	vb, sb, _ := localRun(t, an.m("b"), "run1")
	vc, sc, _ := localRun(t, an.m("c"), "run1")
	if vb != v || vc != v || sb != sc {
		t.Errorf("b holds %d %s, c holds %d %s; want both at %d, the same state", vb, sb, vc, sc, v)
	}
	wantRunEverywhere(t, an, ids, "run1", v, sb)
}

// A step is recorded as running before it runs. That record needs a
// majority of the three masters: with only the owner reachable it is
// refused, so the step does not run. Once recorded, it survives the owner
// dying: a master that missed it (c, down at the time, its hint held by the
// dead owner) has its save from the version before refused, as the save
// reads the run from a majority first, and reads the step as running from
// then on, so the next owner stops the run as unknown instead of running the
// step again.
func TestRunbookRunningStepSurvivesItsOwner(t *testing.T) {
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 3, ids...)
	rb := runbookPreferring(t, ids, "b", "c", "a")
	run := createRun(t, an.m("b"), "run1", rb)
	apEventually(t, "b and c to hold the run", func() bool {
		_, _, onB := localRun(t, an.m("b"), "run1")
		_, _, onC := localRun(t, an.m("c"), "run1")
		return onB && onC
	})

	// b owns the run and reaches no other member: the step is not recorded.
	an.setDown("a", true)
	an.setDown("c", true)
	if _, err := saveRun(t, an.m("b"), run, 1, 1); !errors.Is(err, store.ErrNoMajority) {
		t.Fatalf("record the step running on b alone = %v, want ErrNoMajority", err)
	}

	// a is back: the step is recorded on b and a, then b dies.
	an.setDown("a", false)
	if _, err := saveRun(t, an.m("b"), run, 1, 1); err != nil {
		t.Fatalf("record the step running with a back = %v", err)
	}
	an.setDown("b", true)
	an.setDown("c", false)
	wantRunEverywhere(t, an, []string{"a"}, "run1", 2, `{"step":1}`)
	// The next owner's save is from that version.
	if _, err := saveRun(t, an.m("c"), run, 1, 1); !errors.Is(err, store.ErrRunbookRunConflict) {
		t.Fatalf("save from version 1 after b died = %v, want ErrRunbookRunConflict", err)
	}
	wantRunEverywhere(t, an, []string{"a", "c"}, "run1", 2, `{"step":1}`)
	if _, err := saveRun(t, an.m("c"), run, 2, 2); err != nil {
		t.Fatalf("save from version 2 after b died = %v", err)
	}
}

// The quorum of a runbook run's start and saves is a strict majority of the
// masters (#307, #387): of two sides of a split, at most one has it. Storage
// members never count, however many are live; a member that answered without
// proving the hub CA key is no master, and one that answered a read without a
// proof on that connection gives the read nothing.
func TestRunbookMajority(t *testing.T) {
	for _, tc := range []struct {
		masters []string // a is this member
		storage []string // live storage-only members
		down    []string
		// unproved answered without proving the key.
		unproved []string
		want     int // W
		ok       bool
	}{
		{masters: []string{"a"}, want: 1, ok: true},
		{masters: []string{"a", "b"}, want: 2, ok: true},
		{masters: []string{"a", "b"}, down: []string{"b"}, want: 2},
		{masters: []string{"a", "b"}, storage: []string{"s1", "s2", "s3"}, down: []string{"b"}, want: 2},
		{masters: []string{"a", "b", "c"}, want: 2, ok: true},
		{masters: []string{"a", "b", "c"}, down: []string{"c"}, want: 2, ok: true},
		{masters: []string{"a", "b", "c"}, down: []string{"b", "c"}, want: 2},
		{masters: []string{"a", "b", "c"}, storage: []string{"s1", "s2"}, down: []string{"b", "c"}, want: 2},
		{masters: []string{"a", "b", "c", "d", "e"}, down: []string{"d", "e"}, want: 3, ok: true},
		{masters: []string{"a", "b", "c", "d", "e"}, down: []string{"c", "d", "e"}, want: 3},
		// b proved nothing: two masters, a and c.
		{masters: []string{"a", "b", "c"}, unproved: []string{"b"}, want: 2, ok: true},
		{masters: []string{"a", "b", "c"}, unproved: []string{"b"}, down: []string{"c"}, want: 2},
	} {
		name := fmt.Sprintf("%d-masters/down%v/unproved%v/storage%d", len(tc.masters), tc.down, tc.unproved, len(tc.storage))
		t.Run(name, func(t *testing.T) {
			live := map[string]bool{}
			proved := map[string]bool{}
			for _, m := range slices.Concat(tc.masters, tc.storage) {
				live[m] = !slices.Contains(tc.down, m)
				proved[m] = slices.Contains(tc.masters, m) && !slices.Contains(tc.unproved, m)
			}
			r := &Replicator{proved: proved}
			v := view{self: "a", live: live, masterSet: tc.masters}
			masters, w := r.masterQuorum(v)
			if w != tc.want || w != majority(len(masters)) {
				t.Fatalf("masterQuorum = %v, %d, want W %d", masters, w, tc.want)
			}
			cmd := store.SaveRunbookRun{ID: "run1"}
			err := r.checkMajority(cmd, v)
			if tc.ok != (err == nil) {
				t.Fatalf("checkMajority = %v, want ok %v", err, tc.ok)
			}
			if err != nil && (!errors.Is(err, store.ErrNoMajority) || !errors.Is(err, store.ErrUnavailable)) {
				t.Fatalf("checkMajority = %v, want ErrNoMajority, also ErrUnavailable", err)
			}
			// The read is held to the same majority: this master and the
			// live masters that answered, proving the key.
			answered := map[string]bool{}
			for m := range live {
				answered[m] = live[m]
			}
			if err := r.readMajority(cmd, v, answered); tc.ok != (err == nil) {
				t.Fatalf("readMajority = %v, want ok %v", err, tc.ok)
			}
			// Answers on connections that proved nothing are no majority.
			for _, m := range tc.masters {
				if m != "a" {
					delete(proved, m)
				}
			}
			if err := r.readMajority(cmd, v, answered); len(tc.masters) > 1 && !errors.Is(err, store.ErrNoMajority) {
				t.Fatalf("readMajority with no proof = %v, want ErrNoMajority", err)
			}
		})
	}
}

// A member that started alone, not finding its cluster, is no majority of
// anything: it refuses a runbook run, though its ring is itself alone.
func TestRunbookRefusedWhileStartedAlone(t *testing.T) {
	an := newAPNet(t, 0, "a")
	rb := runbookPreferring(t, []string{"a"}, "a")
	run := createRun(t, an.m("a"), "run1", rb)
	an.m("a").rep.StartAlone()
	if _, err := saveRun(t, an.m("a"), run, 1, 1); !errors.Is(err, store.ErrNoMajority) {
		t.Fatalf("save on a member started alone = %v, want ErrNoMajority", err)
	}
	if v, _, _ := localRun(t, an.m("a"), "run1"); v != 1 {
		t.Fatalf("a holds version %d after the refusal, want 1", v)
	}
}

// A split of three masters (#307, #387): the minority side refuses to start
// a run or record a step, whatever storage members it reaches, and writes
// nothing; the majority side records steps. Once the split heals, the
// minority's save from the version it read is a conflict and a retry from
// the newest version is taken.
func TestRunbookMinorityRefusesAcrossASplit(t *testing.T) {
	for _, tc := range []struct {
		name             string
		ids              []string
		storage          []string // storage-only members, without the hub CA key
		minority, others []string
	}{
		{name: "three members", ids: []string{"a", "b", "c"}, minority: []string{"a"}, others: []string{"b", "c"}},
		// a reaches two storage members, d and e, which say they are
		// masters: they count for nothing, and take no run.
		{
			name: "five members", ids: []string{"a", "b", "c", "d", "e"}, storage: []string{"d", "e"},
			minority: []string{"a", "d", "e"}, others: []string{"b", "c"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Members cut off a moment ago count as up again soon after the heal.
			an := newAPNetWith(t, 3, func(c *ReplicatorConfig) {
				c.SuspectFor = 200 * time.Millisecond
				if slices.Contains(tc.storage, c.NodeID) {
					c.Master = testMasterKey{}
				}
			}, tc.ids...)
			masters := slices.DeleteFunc(slices.Clone(tc.ids), func(m string) bool { return slices.Contains(tc.storage, m) })
			rb := "rb1"
			run := createRun(t, an.m("b"), "run1", rb)
			apEventually(t, "a, b and c to hold the run", func() bool {
				for _, m := range []string{"a", "b", "c"} {
					if _, _, ok := localRun(t, an.m(m), "run1"); !ok {
						return false
					}
				}
				return true
			})

			an.split(tc.minority, tc.others, true)
			for _, m := range tc.minority {
				want := store.ErrNoMajority
				if slices.Contains(tc.storage, m) {
					want = errNotMaster
				}
				if _, err := saveRun(t, an.m(m), run, 1, 1); !errors.Is(err, want) {
					t.Fatalf("save on the minority's %s = %v, want %v", m, err, want)
				}
				other := run
				other.ID = "run2-" + m
				if err := an.m(m).st.RunbookRuns().Create(t.Context(), other); !errors.Is(err, want) {
					t.Fatalf("start a run on the minority's %s = %v, want %v", m, err, want)
				}
			}
			if v, state, _ := localRun(t, an.m("a"), "run1"); v != 1 || state != `{"step":0}` {
				t.Fatalf("a holds version %d, %s after the refusals; want 1, step 0", v, state)
			}
			if _, err := saveRun(t, an.m("b"), run, 1, 1); err != nil {
				t.Fatalf("save on the majority side = %v", err)
			}

			an.split(tc.minority, tc.others, false)
			// The minority read version 1 before the split: refused now.
			apEventually(t, "a's stale save to be decided", func() bool {
				_, err := saveRun(t, an.m("a"), run, 1, 9)
				if err != nil && !errors.Is(err, store.ErrRunbookRunConflict) && !errors.Is(err, store.ErrUnavailable) {
					t.Fatalf("stale save after the heal = %v", err)
				}
				return errors.Is(err, store.ErrRunbookRunConflict)
			})
			if got, err := saveRun(t, an.m("a"), run, 2, 2); err != nil || got != 3 {
				t.Fatalf("retry from version 2 after the heal = %d, %v", got, err)
			}
			for _, id := range tc.ids {
				an.m(id).rep.deliverHints(t.Context())
			}
			wantRunEverywhere(t, an, masters, "run1", 3, `{"step":2}`)
			for _, m := range tc.storage {
				if _, _, ok := localRun(t, an.m(m), "run1"); ok {
					t.Errorf("storage-only %s holds the run", m)
				}
			}
		})
	}
}

// A split the gossip has not noticed yet: b and c still look alive to a but
// cannot be reached. a refuses to start a run or record a step, and writes
// neither, as its read from a majority of the masters fails first.
func TestRunbookMinorityRefusesBeforeTheGossipNotices(t *testing.T) {
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 3, ids...)
	rb := runbookPreferring(t, ids, "a", "b", "c")
	run := createRun(t, an.m("b"), "run1", rb)
	apEventually(t, "a to hold the run", func() bool {
		_, _, ok := localRun(t, an.m("a"), "run1")
		return ok
	})

	an.mu.Lock()
	an.crashed["b"], an.crashed["c"] = true, true
	an.mu.Unlock()
	an.dropConns()
	other := run
	other.ID = "run2"
	if err := an.m("a").st.RunbookRuns().Create(t.Context(), other); !errors.Is(err, store.ErrNoMajority) {
		t.Fatalf("start a run with b and c unreachable = %v, want ErrNoMajority", err)
	}
	if _, _, ok := localRun(t, an.m("a"), "run2"); ok {
		t.Fatal("a stored the run it refused to start")
	}
	if _, err := saveRun(t, an.m("a"), run, 1, 1); !errors.Is(err, store.ErrNoMajority) {
		t.Fatalf("save with b and c unreachable = %v, want ErrNoMajority", err)
	}
	if v, _, _ := localRun(t, an.m("a"), "run1"); v != 1 {
		t.Fatalf("a holds version %d after the refusal, want 1", v)
	}
}

// Runbook runs live on masters only (#387). A storage-only member that says
// on the gossip it is a master, and sorts first, cannot start or save a run,
// nor alter one by any path a forged row could take (a merge, a command to
// coordinate, a hint, anti-entropy, a read); it is not the master a save is
// decided on, is never sent the save, does not count towards the majority,
// and holds no run.
func TestStorageMemberCannotAlterARun(t *testing.T) {
	ctx := t.Context()
	an := newAPNetWith(t, 0, func(c *ReplicatorConfig) {
		if c.NodeID == "a0" {
			c.Master = testMasterKey{}
		}
	}, "a0", "m", "m2")
	forger := an.m("a0")
	run := createRun(t, an.m("m"), "run1", "rb1")
	apEventually(t, "m2 to hold the run", func() bool {
		_, _, ok := localRun(t, an.m("m2"), "run1")
		return ok
	})

	// Its own store starts and saves none.
	other := run
	other.ID = "run2"
	if err := forger.st.RunbookRuns().Create(ctx, other); !errors.Is(err, errNotMaster) {
		t.Fatalf("start a run on a storage member = %v, want errNotMaster", err)
	}
	if _, err := saveRun(t, forger, run, 1, 1); !errors.Is(err, errNotMaster) {
		t.Fatalf("save a run on a storage member = %v, want errNotMaster", err)
	}

	// A forged save, stamped as if m wrote it: refused as a merge, as a
	// command for m to coordinate, as a hint, and by anti-entropy.
	if _, _, err := forger.st.ApplyLocalMutations(ctx, store.CreateRunbookRun{
		Stamp: store.Stamp{HLC: hlc.New(time.Now()), Origin: "m"},
		ID:    "run1", RunbookID: "rb1", Status: "running", StartedBy: "web/x", StartedAt: 1, Source: []byte("evil"),
		State: `{"step":7}`, Keep: store.RunbookRunsKept,
	}); err != nil {
		t.Fatal(err)
	}
	forged, err := forger.st.ReadRows(ctx, []store.RowRef{{Table: "runbook_runs", Key: store.Values{"run1"}}})
	if err != nil || len(forged) != 1 {
		t.Fatalf("the forged run on a0: %v, %v", forged, err)
	}
	forged[0].HLC += 1 << 40
	for _, m := range []string{"m", "m2"} {
		if _, err := forger.rep.call(ctx, m, apRequest{Op: opMerge, Muts: forged}); !errors.Is(err, errNotMaster) {
			t.Fatalf("merge of a forged run into %s = %v, want errNotMaster", m, err)
		}
	}
	b, err := store.EncodeCommand(store.SaveRunbookRun{ID: "run1", Version: 1, Status: "running", State: `{"step":7}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forger.rep.call(ctx, "m", apRequest{Op: opApply, Cmd: b}); !errors.Is(err, errNotMaster) {
		t.Fatalf("a save for m to coordinate = %v, want errNotMaster", err)
	}
	if err := forger.hints.Add("m", forged); err != nil {
		t.Fatal(err)
	}
	forger.rep.deliverHints(ctx)
	for _, p := range [][2]string{{"m", "a0"}, {"a0", "m"}, {"m2", "a0"}, {"a0", "m2"}} {
		if err := an.m(p[0]).rep.SyncWith(ctx, p[1]); err != nil {
			t.Fatalf("anti-entropy of %s with %s: %v", p[0], p[1], err)
		}
	}
	if _, err := forger.rep.call(ctx, "m", apRequest{Op: opRead, Query: `SELECT state FROM runbook_runs`}); !errors.Is(err, errNotMaster) {
		t.Fatalf("a0 read the runs on m: %v, want errNotMaster", err)
	}
	wantRunEverywhere(t, an, []string{"m", "m2"}, "run1", 1, `{"step":0}`)

	// The masters save it, a0 sorting first and claiming master: the save
	// is decided on m, a majority of the two masters takes it, and a0 is
	// never sent it.
	for i, m := range []string{"m2", "m"} {
		if _, err := saveRun(t, an.m(m), run, int64(1+i), 1+i); err != nil {
			t.Fatalf("save %d on %s = %v", i+1, m, err)
		}
	}
	wantRunEverywhere(t, an, []string{"m", "m2"}, "run1", 3, `{"step":2}`)
	if v, state, _ := localRun(t, forger, "run1"); state != `{"step":7}` || v != 1 {
		t.Fatalf("a0 holds the run at %d, %s: want only its own forged copy", v, state)
	}
	// With m2 down, m alone is no majority of the two masters, a0 or not.
	an.setDown("m2", true)
	if _, err := saveRun(t, an.m("m"), run, 3, 3); !errors.Is(err, store.ErrNoMajority) {
		t.Fatalf("save with m2 down = %v, want ErrNoMajority", err)
	}
}
