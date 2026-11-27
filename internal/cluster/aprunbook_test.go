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

	"github.com/gvart/hearth/internal/store"
)

// Runbook run saves in a sharded cluster (#292). A run's saves are decided
// by its version: a save from a version the run has moved past is refused,
// so a step is recorded as running once and never run twice. These tests
// hold that check to the newest copy of the run, whichever replica applies
// the save. Hints and anti-entropy run hourly here, so a stale copy stays
// stale until the test delivers the hints.

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

// A save applied on a replica that missed the run's last saves decides on
// the newest copy: a save from the version it holds is refused, and one
// from the newest version is taken. No save is lost, and every master reads
// the run at its newest version. Three replicas, so the saves b misses still
// reach a majority of them.
func TestRunbookSaveOnAStaleReplica(t *testing.T) {
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 3, ids...)
	rb := runbookPreferring(t, ids, "b", "c", "a")
	run := createRun(t, an.m("a"), "run1", rb)
	apEventually(t, "b and c to hold the run", func() bool {
		_, _, onB := localRun(t, an.m("b"), "run1")
		_, _, onC := localRun(t, an.m("c"), "run1")
		return onB && onC
	})

	// b, the run's first replica, misses two saves.
	an.setDown("b", true)
	v := int64(1)
	for step := 1; step <= 2; step++ {
		next, err := saveRun(t, an.m("c"), run, v, step)
		if err != nil {
			t.Fatalf("save of step %d with b down = %v", step, err)
		}
		v = next
	}
	an.setDown("b", false)
	if got, _, _ := localRun(t, an.m("b"), "run1"); got != 1 {
		t.Fatalf("b holds version %d; the test needs it stale at 1", got)
	}

	// A hub that read the run before those saves: refused, though b's copy
	// is at the version it read.
	if _, err := saveRun(t, an.m("b"), run, 1, 9); !errors.Is(err, store.ErrRunbookRunConflict) {
		t.Fatalf("save from version 1 on the stale b = %v, want ErrRunbookRunConflict", err)
	}
	// A hub that read the newest version: taken, though it goes to b first.
	if got, err := saveRun(t, an.m("a"), run, v, 3); err != nil || got != v+1 {
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
// majority of the run's three replicas: with only the owner's own replica
// reachable it is refused, so the step does not run. Once recorded, it
// survives the owner dying, and every other master reads the step as
// running, so the next owner stops the run as unknown instead of running the
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
	wantRunEverywhere(t, an, []string{"a", "c"}, "run1", 2, `{"step":1}`)
	// The next owner's save is from that version.
	if _, err := saveRun(t, an.m("c"), run, 1, 1); !errors.Is(err, store.ErrRunbookRunConflict) {
		t.Fatalf("save from version 1 after b died = %v, want ErrRunbookRunConflict", err)
	}
	if _, err := saveRun(t, an.m("c"), run, 2, 2); err != nil {
		t.Fatalf("save from version 2 after b died = %v", err)
	}
}

// The quorum of a runbook run's saves is a strict majority of its N replicas,
// stand-ins never counted (#307): of two sides of a split, at most one has it.
func TestRunbookMajority(t *testing.T) {
	for _, tc := range []struct {
		members []string
		n       int
		down    []string // members down; the key's replicas are the first n members
		want    int      // W
		ok      bool
	}{
		{members: []string{"a"}, n: 1, want: 1, ok: true},
		{members: []string{"a", "b"}, n: 2, want: 2, ok: true},
		{members: []string{"a", "b"}, n: 2, down: []string{"b"}, want: 2},
		{members: []string{"a", "b", "c"}, n: 2, down: []string{"b"}, want: 2}, // c stands in, uncounted
		{members: []string{"a", "b", "c"}, n: 3, want: 2, ok: true},
		{members: []string{"a", "b", "c"}, n: 3, down: []string{"c"}, want: 2, ok: true},
		{members: []string{"a", "b", "c"}, n: 3, down: []string{"b", "c"}, want: 2},
		{members: []string{"a", "b", "c", "d", "e"}, n: 3, down: []string{"b", "c"}, want: 2}, // d and e stand in
		{members: []string{"a", "b", "c", "d", "e"}, n: 5, down: []string{"d", "e"}, want: 3, ok: true},
		{members: []string{"a", "b", "c", "d", "e"}, n: 5, down: []string{"c", "d", "e"}, want: 3},
	} {
		t.Run(fmt.Sprintf("n%d/%d-members/down%v", tc.n, len(tc.members), tc.down), func(t *testing.T) {
			if got := majority(tc.n); got != tc.want {
				t.Fatalf("majority(%d) = %d, want %d", tc.n, got, tc.want)
			}
			key := runbookPreferring(t, tc.members, tc.members[:tc.n]...)
			live := map[string]bool{}
			for _, m := range tc.members {
				live[m] = !slices.Contains(tc.down, m)
			}
			v := view{self: "a", ring: NewRing(tc.members), live: live, n: tc.n, syncing: map[string]bool{}}
			cmd := store.SaveRunbookRun{ID: "run1", RunbookID: key}
			err := (&Replicator{}).checkMajority(cmd, key, v)
			if tc.ok != (err == nil) {
				t.Fatalf("checkMajority = %v, want ok %v", err, tc.ok)
			}
			if err != nil && (!errors.Is(err, store.ErrNoMajority) || !errors.Is(err, store.ErrUnavailable)) {
				t.Fatalf("checkMajority = %v, want ErrNoMajority, also ErrUnavailable", err)
			}
			// The read is held to the same majority: this member and the
			// live replicas that answered.
			answered := map[string]bool{}
			for _, m := range tc.members {
				answered[m] = live[m]
			}
			if err := readMajority(cmd, key, v, answered); tc.ok != (err == nil) {
				t.Fatalf("readMajority = %v, want ok %v", err, tc.ok)
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

// A split of a run's three replicas (#307): the minority side refuses to
// start a run or record a step, whatever stand-ins it reaches, and writes
// nothing; the majority side records steps. Once the split heals, the
// minority's save from the version it read is a conflict and a retry from
// the newest version is taken.
func TestRunbookMinorityRefusesAcrossASplit(t *testing.T) {
	for _, tc := range []struct {
		name             string
		ids              []string
		minority, others []string
	}{
		{name: "three members", ids: []string{"a", "b", "c"}, minority: []string{"a"}, others: []string{"b", "c"}},
		// a reaches two stand-ins, d and e: on main it took the save.
		{name: "five members", ids: []string{"a", "b", "c", "d", "e"}, minority: []string{"a", "d", "e"}, others: []string{"b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Members cut off a moment ago count as up again soon after the heal.
			an := newAPNetWith(t, 3, func(c *ReplicatorConfig) { c.SuspectFor = 200 * time.Millisecond }, tc.ids...)
			rb := runbookPreferring(t, tc.ids, "a", "b", "c")
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
				if _, err := saveRun(t, an.m(m), run, 1, 1); !errors.Is(err, store.ErrNoMajority) {
					t.Fatalf("save on the minority's %s = %v, want ErrNoMajority", m, err)
				}
				other := run
				other.ID = "run2-" + m
				if err := an.m(m).st.RunbookRuns().Create(t.Context(), other); !errors.Is(err, store.ErrNoMajority) {
					t.Fatalf("start a run on the minority's %s = %v, want ErrNoMajority", m, err)
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
			wantRunEverywhere(t, an, tc.ids, "run1", 3, `{"step":2}`)
		})
	}
}

// A split the gossip has not noticed yet: b and c still look alive to a but
// cannot be reached. a refuses to start a run or record a step, and writes
// neither, as its read from a majority of the replicas fails first.
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
