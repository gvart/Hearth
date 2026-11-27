// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// staleReader serves the ceiling a heartbeat read before an admin lowered
// it: shell on, at version 5.
type staleReader struct{}

func (staleReader) Get(context.Context, string) (store.DeviceCeiling, error) {
	return store.DeviceCeiling{Ceiling: []byte(`{"shell":true}`), Version: 5}, nil
}

func pushSession(sent *[]*agentv1.CeilingConfig, mu *sync.Mutex) *agentSession {
	return &agentSession{
		device: "pi", minor: minCeilingConfigMinor, sendTimeout: time.Second, done: make(chan struct{}),
		abort: func() {},
		send: func(m *agentv1.HubMessage) error {
			mu.Lock()
			defer mu.Unlock()
			*sent = append(*sent, m.GetCeilingConfig())
			return nil
		},
	}
}

// TestStalePushNeverUndoesALowering: a heartbeat sync that read the stored
// ceiling (shell on, version 5) before an admin lowered it (version 6) and
// pushes after the lowering's push sends nothing: the agent keeps version 6.
func TestStalePushNeverUndoesALowering(t *testing.T) {
	ctx := t.Context()
	st := newTestStore(t)
	var (
		mu   sync.Mutex
		sent []*agentv1.CeilingConfig
	)
	sess := pushSession(&sent, &mu)

	// The lowering: stored and pushed.
	if err := st.DeviceCeilings().Set(ctx, "pi", []byte(`{}`), "web/a", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sess.syncCeiling(ctx, st.DeviceCeilings()); err != nil {
		t.Fatal(err)
	}
	lowered := sent[len(sent)-1]
	if lowered.GetCeiling().GetShell() || lowered.GetVersion() == 0 {
		t.Fatalf("lowering pushed %v", lowered)
	}

	// The stale heartbeat, read before the lowering, lands after it.
	stale := staleReader{}
	if lowered.GetVersion() <= 5 {
		t.Fatalf("lowering version %d; the test needs it above the stale 5", lowered.GetVersion())
	}
	if err := sess.syncCeiling(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if n := len(sent); n != 1 {
		t.Fatalf("stale push sent: %v", sent[n-1])
	}

	// A later change still goes through.
	if err := st.DeviceCeilings().Set(ctx, "pi", []byte(`{"probe":true}`), "web/a", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sess.syncCeiling(ctx, st.DeviceCeilings()); err != nil {
		t.Fatal(err)
	}
	if last := sent[len(sent)-1]; !last.GetCeiling().GetProbe() || last.GetVersion() <= lowered.GetVersion() {
		t.Fatalf("later change pushed %v", last)
	}
}

// TestCeilingPushesInterleaved: heartbeat syncs racing PUTs, each storing a
// new ceiling and pushing it, send versions that never go back.
func TestCeilingPushesInterleaved(t *testing.T) {
	ctx := t.Context()
	st := newTestStore(t)
	var (
		mu   sync.Mutex
		sent []*agentv1.CeilingConfig
	)
	sess := pushSession(&sent, &mu)
	agents := &Agents{sessions: map[string]*agentSession{"pi": sess}}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			body := `{"shell":true}`
			if i%2 == 0 {
				body = `{}`
			}
			if err := st.DeviceCeilings().Set(ctx, "pi", []byte(body), "web/a", time.Now()); err != nil {
				t.Error(err)
				return
			}
			if err := agents.PushCeiling(ctx, st.DeviceCeilings(), "pi"); err != nil {
				t.Error(err)
			}
		})
		wg.Go(func() {
			if err := sess.syncCeiling(ctx, st.DeviceCeilings()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < len(sent); i++ {
		if sent[i].GetVersion() < sent[i-1].GetVersion() {
			t.Fatalf("push %d went back from version %d to %d", i, sent[i-1].GetVersion(), sent[i].GetVersion())
		}
	}
	stored, err := storedCeiling(ctx, st.DeviceCeilings(), "pi")
	if err != nil {
		t.Fatal(err)
	}
	if last := sent[len(sent)-1]; last.GetVersion() != stored.GetVersion() {
		t.Errorf("last push version %d, stored %d", last.GetVersion(), stored.GetVersion())
	}
}
