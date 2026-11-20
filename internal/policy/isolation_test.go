// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

// TestFailClosedWhenIsolated: an isolated master denies dangerous actions
// and enrollments, audited with the reason, and keeps allowing safe ones;
// the block clears when it is no longer isolated.
func TestFailClosedWhenIsolated(t *testing.T) {
	audit := &memAudit{}
	e := New(audit)
	var isolated atomic.Bool
	e.FailClosedWhen(isolated.Load)
	run := func(req Request) error {
		return e.Do(t.Context(), req, func(context.Context) error { return nil })
	}
	drain := Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: KubeNodeDrain, Target: "lab/pi-1"}
	enroll := Request{ActorKind: ActorToken, ActorID: "tok", Action: DeviceEnroll, Target: "pi"}
	safe := Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: KubePodDelete, Target: "lab/web"}

	if err := run(drain); err != nil {
		t.Fatalf("dangerous action while connected = %v", err)
	}
	isolated.Store(true)
	for _, req := range []Request{drain, enroll} {
		if err := run(req); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), ErrIsolated) {
			t.Errorf("%s while isolated = %v, want a denial for isolation", req.Action, err)
		}
	}
	audit.mu.Lock()
	last := audit.entries[len(audit.entries)-1]
	audit.mu.Unlock()
	if last.Decision != string(Deny) || !strings.Contains(last.Result, ErrIsolated) {
		t.Errorf("audit of the isolated denial = %+v", last)
	}
	if err := run(safe); err != nil {
		t.Errorf("safe action while isolated = %v", err)
	}
	isolated.Store(false)
	if err := run(drain); err != nil {
		t.Errorf("dangerous action after recovery = %v", err)
	}
}
