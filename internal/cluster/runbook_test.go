// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// plainSealer leaves the runbook's copy as it is.
type plainSealer struct{}

func (plainSealer) Seal(_ string, b []byte) ([]byte, error) { return b, nil }
func (plainSealer) Open(_ string, b []byte) ([]byte, error) { return b, nil }

// countedAction counts its runs and blocks on gate while it is set.
type countedAction struct {
	name string
	runs *sync.Map
	gate *atomic.Pointer[chan struct{}]
}

func (a *countedAction) Describe() string      { return "count " + a.name }
func (a *countedAction) Policy() policy.Action { return policy.AutomationRestart }
func (a *countedAction) Target() automation.Text {
	return automation.Literal(a.name)
}

func (a *countedAction) Run(ctx context.Context, _ automation.Event) error {
	n, _ := a.runs.LoadOrStore(a.name, new(atomic.Int64))
	n.(*atomic.Int64).Add(1) //nolint:forcetypeassert // only *atomic.Int64 is stored
	if g := a.gate.Load(); g != nil && a.name == "two" {
		select {
		case <-*g:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

const clusterRunbook = `id: rb
steps:
  - id: one
    type: action
    action: {type: counted, name: one}
  - id: two
    type: action
    action: {type: counted, name: two}
  - id: three
    type: action
    action: {type: counted, name: three}
`

// TestRunbookSurvivesALeaderChange runs a runbook on the leader of a real
// cluster, kills the leader in the middle of a step, and checks that the new
// leader neither repeats the completed step nor re-runs the interrupted one.
func TestRunbookSurvivesALeaderChange(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: 5 * time.Second, flushEvery: time.Minute})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rb.yaml"), []byte(clusterRunbook), 0o600); err != nil {
		t.Fatal(err)
	}
	var (
		runs sync.Map
		gate atomic.Pointer[chan struct{}]
	)
	release := make(chan struct{})
	gate.Store(&release)
	kinds := automation.Builtin(slog.New(slog.DiscardHandler))
	kinds.Actions["counted"] = func(p automation.Params) (automation.Action, error) {
		var c struct {
			Name string `yaml:"name"`
		}
		if err := p.Decode(&c); err != nil {
			return nil, err
		}
		return &countedAction{name: c.Name, runs: &runs, gate: &gate}, nil
	}
	count := func(name string) int64 {
		n, ok := runs.Load(name)
		if !ok {
			return 0
		}
		return n.(*atomic.Int64).Load() //nolint:forcetypeassert // only *atomic.Int64 is stored
	}
	engine := func(h *testHub) *automation.Runbooks {
		return automation.NewRunbooks(automation.RunbooksConfig{
			Dir: dir, Kinds: kinds, Policy: policy.New(h.st.Audit()), Runs: h.st.RunbookRuns(), Sealer: plainSealer{},
			Poll: 20 * time.Millisecond,
		})
	}

	leader := leaderHub(t, hubs)
	first := engine(leader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_ = first.Run(ctx)
	}()

	// A run started through a follower reaches the leader's engine.
	follower := followers(hubs, leader)[0]
	run, err := engine(follower).Start(ctx, policy.ActorWeb, "10.0.0.1", "rb")
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "step two running on the leader", func() bool { return count("two") == 1 })
	eventually(t, "the follower to see step two running", func() bool {
		r, err := follower.st.RunbookRuns().Get(t.Context(), run.ID)
		if err != nil {
			return false
		}
		var st automation.RunbookState
		return json.Unmarshal(r.State, &st) == nil && len(st.Steps) == 3 && st.Steps[1].Status == "running"
	})

	// The leader dies in the middle of step two.
	cancel()
	<-firstDone
	leader.kill()
	rest := followers(hubs, leader)
	next := leaderHub(t, rest)
	second := engine(next)
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		_ = second.Run(ctx2)
	}()
	defer func() {
		cancel2()
		<-done2
	}()

	eventually(t, "the run to stop for the operator", func() bool {
		r, err := second.GetRun(t.Context(), run.ID)
		return err == nil && r.Status == automation.RunbookUnknown
	})
	time.Sleep(200 * time.Millisecond)
	if one, two, three := count("one"), count("two"), count("three"); one != 1 || two != 1 || three != 0 {
		t.Fatalf("runs: one %d, two %d, three %d; want 1, 1, 0", one, two, three)
	}

	// The operator retries: the step runs again, and the run finishes.
	close(release)
	if _, err := second.Retry(t.Context(), policy.ActorWeb, "10.0.0.1", run.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the run to finish", func() bool {
		r, err := second.GetRun(t.Context(), run.ID)
		return err == nil && r.Status == automation.RunbookSucceeded
	})
	if one, two, three := count("one"), count("two"), count("three"); one != 1 || two != 2 || three != 1 {
		t.Errorf("runs: one %d, two %d, three %d; want 1, 2, 1", one, two, three)
	}
	// Every surviving hub holds the same run.
	for _, h := range rest {
		eventually(t, "the finished run on "+h.ID(), func() bool {
			r, err := h.st.RunbookRuns().Get(t.Context(), run.ID)
			return err == nil && r.Status == automation.RunbookSucceeded
		})
	}
}

// TestRunbookConflictDoesNotHaltTheCluster checks that a lost compare-and-swap
// is an outcome of the command: applying it must not stop a hub.
func TestRunbookConflictDoesNotHaltTheCluster(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: 5 * time.Second, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	f := followers(hubs, leader)[0]
	ctx := t.Context()
	now := time.Now()
	run := store.RunbookRun{
		ID: "r", RunbookID: "rb", Status: automation.RunbookRunning, StartedBy: "web/x", StartedAt: now, UpdatedAt: now,
		Source: []byte("x"), State: json.RawMessage(`{}`), Version: 1,
	}
	if err := f.st.RunbookRuns().Create(ctx, run); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.RunbookRuns().Save(ctx, run); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.RunbookRuns().Save(ctx, run); !errors.Is(err, store.ErrRunbookRunConflict) {
		t.Fatalf("stale save through a follower = %v, want a conflict", err)
	}
	upsert(t, leader.testNode, "still-writing")
	for _, h := range hubs {
		eventually(t, "the cluster to keep applying on "+h.ID(), func() bool { return hasDevice(h.testNode, "still-writing") })
	}
}
