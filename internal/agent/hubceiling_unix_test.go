// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package agent

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// TestLogStreamEndsWhenTurnedOff lowers the ceiling under an open stream:
// the agent ends it itself and tells the hub it was denied; a stream the
// new ceiling still allows goes on.
func TestLogStreamEndsWhenTurnedOff(t *testing.T) {
	t.Parallel()
	l, _ := fakeLogs(t, Ceiling{Logs: []string{"docker:*", "systemd:keep.service"}}, loopScript)
	var off, kept logCollector
	offDone, keptDone := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		defer close(offDone)
		l.stream(ctx, &agentv1.LogRequest{Id: "off", Source: &agentv1.LogSource{Manager: "docker", Name: "web"}}, off.send)
	}()
	go func() {
		defer close(keptDone)
		l.stream(ctx, &agentv1.LogRequest{Id: "kept", Source: &agentv1.LogSource{Manager: "systemd", Name: "keep.service"}}, kept.send)
	}()
	eventually(t, "lines on both streams", func() bool {
		a, _ := off.lines()
		b, _ := kept.lines()
		return a > 0 && b > 0
	})
	l.setCeiling(t.Context(), Ceiling{Logs: []string{"systemd:keep.service"}})
	select {
	case <-offDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream turned off is still open")
	}
	if _, last := off.lines(); !last.GetEnd() || !last.GetDenied() {
		t.Errorf("last message %v, want an end, denied", last)
	}
	select {
	case <-keptDone:
		t.Fatal("the stream still allowed ended")
	case <-time.After(100 * time.Millisecond):
	}
	// A new stream of the source turned off is refused.
	var again logCollector
	l.stream(t.Context(), &agentv1.LogRequest{Id: "again", Source: &agentv1.LogSource{Manager: "docker", Name: "web"}}, again.send)
	if _, last := again.lines(); !last.GetDenied() {
		t.Errorf("new stream after turning off: %v, want denied", last)
	}
	cancel()
	<-keptDone
	l.wait()
}

// TestShellEndsWhenTurnedOff lowers the ceiling under an open shell: the
// agent ends it, and refuses the next one.
func TestShellEndsWhenTurnedOff(t *testing.T) {
	t.Parallel()
	r := newShellRig(t, Ceiling{Shell: true})
	r.send(open())
	if started := r.next(t).GetStarted(); started == nil {
		t.Fatal("shell did not start")
	}
	r.h.setCeiling(r.ctx, Ceiling{})
	if ex := r.exited(t); ex.GetError() == "" {
		t.Errorf("exit = %v, want the session closed", ex)
	}
	r.send(open())
	if ex := r.next(t).GetExited(); ex == nil || !ex.GetDenied() {
		t.Errorf("shell after turning off: %v, want denied", ex)
	}
}
