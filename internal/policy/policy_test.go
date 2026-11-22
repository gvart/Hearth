// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

func TestEngineDo(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name         string
		req          Request
		fnErr        error
		wantRan      bool
		wantErr      error
		wantDecision string
		wantResult   string
	}{
		{
			name:         "allowed and ok",
			req:          Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi", Detail: map[string]any{"n": 1}},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "allowed but action fails",
			req:          Request{ActorKind: ActorToken, ActorID: "abc", Action: DeviceEnroll},
			fnErr:        boom,
			wantRan:      true,
			wantErr:      boom,
			wantDecision: Allow,
			wantResult:   "error: boom",
		},
		{
			name:         "unknown action denied",
			req:          Request{ActorKind: ActorAdmin, ActorID: "root", Action: "device.reboot"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "unknown action",
		},
		{
			name:         "wrong actor kind denied",
			req:          Request{ActorKind: ActorToken, ActorID: "abc", Action: DeviceRevoke},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web login allowed",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: AdminLogin},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "MCP client cannot set the admin password",
			req:          Request{ActorKind: ActorMCP, ActorID: "claude", Action: AdminSetPassword},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web session can set telemetry",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: TelemetrySet, Detail: map[string]any{"enabled": true}},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "MCP client cannot set telemetry",
			req:          Request{ActorKind: ActorMCP, ActorID: "claude", Action: TelemetrySet},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "automation cannot set telemetry",
			req:          Request{ActorKind: ActorAutomation, ActorID: "a", Action: TelemetrySet},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web session can create a token",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: TokenCreate},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "agent token cannot create a token",
			req:          Request{ActorKind: ActorToken, ActorID: "abc", Action: TokenCreate},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "agent token cannot log in",
			req:          Request{ActorKind: ActorToken, ActorID: "abc", Action: AdminLogin},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "join token can join the cluster",
			req:          Request{ActorKind: ActorJoinToken, ActorID: "abc", Action: ClusterJoin},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "enrollment token cannot join the cluster",
			req:          Request{ActorKind: ActorToken, ActorID: "abc", Action: ClusterJoin},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "hub-eligible enrollment token mints its device's join token",
			req:          Request{ActorKind: ActorToken, ActorID: "abc", Action: ClusterTokenCreate},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "MCP client cannot create a join token",
			req:          Request{ActorKind: ActorMCP, ActorID: "claude", Action: ClusterTokenCreate},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "automation cannot rotate the hub CA",
			req:          Request{ActorKind: ActorAutomation, ActorID: "nightly", Action: ClusterCARotate},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "join token cannot promote",
			req:          Request{ActorKind: ActorJoinToken, ActorID: "abc", Action: ClusterPromote},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "admin can remove a hub",
			req:          Request{ActorKind: ActorAdmin, ActorID: "root", Action: ClusterRemove, Target: "hub-c"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "hub can remove a member down for good",
			req:          Request{ActorKind: ActorHub, ActorID: "hub-b", Action: ClusterRemove, Target: "hub-c"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "join token cannot remove a hub",
			req:          Request{ActorKind: ActorJoinToken, ActorID: "abc", Action: ClusterRemove, Target: "hub-c"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "automation can log",
			req:          Request{ActorKind: ActorAutomation, ActorID: "hello", Action: AutomationLog},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   ReadAllowed,
		},
		{
			name:         "web session cannot run an automation's action",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: AutomationLog},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "anonymous automation denied",
			req:          Request{ActorKind: ActorAutomation, Action: AutomationLog},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "anonymous actor",
		},
		{
			name:         "automation can call a webhook",
			req:          Request{ActorKind: ActorAutomation, ActorID: "hello", Action: AutomationWebhook},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "automation can restart a service",
			req:          Request{ActorKind: ActorAutomation, ActorID: "hello", Action: AutomationRestart, Target: "pi"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "automation without a grant cannot exec",
			req:          Request{ActorKind: ActorAutomation, ActorID: "hello", Action: AutomationExec, Target: "pi"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "dangerous action not granted to this automation",
		},
		{
			name:         "granted automation can exec",
			req:          Request{ActorKind: ActorAutomation, ActorID: "trusted", Action: AutomationExec, Target: "pi"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "a grant is not an actor kind: admin cannot exec through automations",
			req:          Request{ActorKind: ActorAdmin, ActorID: "trusted", Action: AutomationExec, Target: "pi"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web session cannot restart a service",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: AutomationRestart},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web session can add a kube cluster",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: KubeClusterAdd, Target: "lab"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "agent token cannot add a kube cluster",
			req:          Request{ActorKind: ActorToken, ActorID: "abc", Action: KubeClusterAdd, Target: "lab"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "hub cannot remove a kube cluster",
			req:          Request{ActorKind: ActorHub, ActorID: "hub-b", Action: KubeClusterRemove, Target: "lab"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web session can read pod logs",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: KubePodLogs, Target: "lab/default/web"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   ReadAllowed,
		},
		{
			name:         "automation cannot read pod logs",
			req:          Request{ActorKind: ActorAutomation, ActorID: "a", Action: KubePodLogs, Target: "lab/default/web"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web session can drain a node",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: KubeNodeDrain, Target: "lab/pi-1"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "ungranted automation cannot drain a node",
			req:          Request{ActorKind: ActorAutomation, ActorID: "nightly", Action: KubeNodeDrain, Target: "lab/pi-1"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "dangerous action not granted to this automation",
		},
		{
			name:         "granted automation can drain a node",
			req:          Request{ActorKind: ActorAutomation, ActorID: "trusted", Action: KubeNodeDrain, Target: "lab/pi-1"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "automation can restart a workload",
			req:          Request{ActorKind: ActorAutomation, ActorID: "nightly", Action: KubeWorkloadRestart, Target: "lab/Deployment/default/web"},
			wantRan:      true,
			wantDecision: Allow,
			wantResult:   "ok",
		},
		{
			name:         "agent token cannot scale a workload",
			req:          Request{ActorKind: ActorToken, ActorID: "abc", Action: KubeWorkloadScale, Target: "lab/default/web"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "anonymous web session cannot delete a pod",
			req:          Request{ActorKind: ActorWeb, Action: KubePodDelete, Target: "lab/default/web-1"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "anonymous actor",
		},
		{
			name:         "anonymous actor denied",
			req:          Request{ActorKind: ActorAdmin, Action: TokenCreate},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "anonymous actor",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			s, err := store.Open(ctx, filepath.Join(t.TempDir(), "hearth.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })

			ran := false
			pol := NewWithConfig(s.Audit(), s.Approvals(), Config{DangerousAutomations: []string{"trusted"}})
			err = pol.Do(ctx, tt.req, func(context.Context) error {
				ran = true
				return tt.fnErr
			})
			if ran != tt.wantRan {
				t.Errorf("ran = %v, want %v", ran, tt.wantRan)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}

			entries, err := s.Audit().List(ctx, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("audit entries = %d, want exactly 1", len(entries))
			}
			e := entries[0]
			if e.Decision != tt.wantDecision || e.Result != tt.wantResult || e.Action != string(tt.req.Action) {
				t.Errorf("audit = %+v, want decision %q result %q", e, tt.wantDecision, tt.wantResult)
			}
		})
	}
}

// failingAudit is an Auditor whose appends fail with err.
type failingAudit struct{ err error }

func (f failingAudit) Append(context.Context, store.AuditEntry) (int64, error) { return 0, f.err }

// TestEngineDoOutcomeAuditFailure: an action that ran reports what happened
// to it and that its outcome is missing from the audit log.
func TestEngineDoOutcomeAuditFailure(t *testing.T) {
	req := Request{ActorKind: ActorAdmin, ActorID: "root", Action: TokenCreate}
	unavailable := fmt.Errorf("forward: %w", store.ErrUnavailable)
	disk := errors.New("disk full")
	tests := []struct {
		name     string
		runErr   error
		auditErr error
		wantIs   []error
		wantNot  []error
		wantMsg  string
	}{
		{
			"action ok, audit fails", nil, disk,
			[]error{ErrOutcomeNotRecorded},
			[]error{disk},
			"token.create ran, but its outcome was not recorded: audit token.create: disk full",
		},
		{
			"same cause reported once", fmt.Errorf("create token: %w", unavailable), unavailable,
			[]error{store.ErrUnavailable, ErrOutcomeNotRecorded},
			nil,
			"create token: forward: " + store.ErrUnavailable.Error() + " (its outcome was not recorded either)",
		},
		{
			"different causes both kept", store.ErrTokenUsed, disk,
			[]error{store.ErrTokenUsed, ErrOutcomeNotRecorded},
			[]error{disk},
			store.ErrTokenUsed.Error() + " (its outcome was not recorded: audit token.create: disk full)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audit := &scriptedAudit{failFrom: 2, err: tt.auditErr}
			err := New(audit).Do(t.Context(), req, func(context.Context) error { return tt.runErr })
			for _, target := range tt.wantIs {
				if !errors.Is(err, target) {
					t.Errorf("err = %v, want it to match %v", err, target)
				}
			}
			for _, target := range tt.wantNot {
				if errors.Is(err, target) {
					t.Errorf("err = %v, want it not to match %v", err, target)
				}
			}
			if err == nil || err.Error() != tt.wantMsg {
				t.Errorf("message = %q, want %q", err, tt.wantMsg)
			}
		})
	}
}

// stuckAudit is an audit log whose writes hang until their context ends.
type stuckAudit struct{}

func (stuckAudit) Append(ctx context.Context, _ store.AuditEntry) (int64, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

// TestAuditWriteIsBounded is a stuck store: the request ends, and the action
// it could not audit first is not run.
func TestAuditWriteIsBounded(t *testing.T) {
	e := New(stuckAudit{})
	e.auditTimeout = 50 * time.Millisecond
	ran := false
	start := time.Now()
	err := e.Do(t.Context(), Request{ActorKind: ActorAdmin, ActorID: "root", Action: TokenCreate},
		func(context.Context) error {
			ran = true
			return nil
		})
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Do took %s", d)
	}
	if ran || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "nothing was run") {
		t.Fatalf("Do = %v (ran %v), want a timeout that says nothing was run", err, ran)
	}
}

func TestBeyondCeilingIsADenial(t *testing.T) {
	if !errors.Is(fmt.Errorf("exec on pi: %w", ErrBeyondCeiling), ErrDenied) {
		t.Error("ErrBeyondCeiling does not match ErrDenied")
	}
}

// Only the context Do passes to an allowed action is granted it, and only
// that action; a denial grants nothing.
func TestGranted(t *testing.T) {
	if Granted(t.Context(), KubeNodeDrain) {
		t.Fatal("a plain context is granted")
	}
	e := New(&memAudit{})
	var got, other, carried bool
	req := Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: KubeNodeDrain, Target: "lab/pi-1"}
	if err := e.Do(t.Context(), req, func(ctx context.Context) error {
		got, other = Granted(ctx, KubeNodeDrain), Granted(ctx, KubePodDelete)
		carried = Granted(WithGrant(context.Background(), ctx), KubeNodeDrain)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !got || other || !carried {
		t.Errorf("granted = %v, other action = %v, carried = %v; want true, false, true", got, other, carried)
	}
	if Granted(WithGrant(t.Context(), t.Context()), KubeNodeDrain) {
		t.Error("WithGrant made a grant from nothing")
	}

	ran := false
	denied := Request{ActorKind: ActorAutomation, ActorID: "nightly", Action: KubeNodeDrain, Target: "lab/pi-1"}
	if err := e.Do(t.Context(), denied, func(context.Context) error { ran = true; return nil }); !errors.Is(err, ErrDenied) || ran {
		t.Errorf("ungranted automation drain: err = %v, ran = %v", err, ran)
	}
}

func TestEveryActionHasAClass(t *testing.T) {
	for a, r := range rules {
		switch r.class {
		case Read, Safe, Dangerous:
		default:
			t.Errorf("action %s has invalid class %q", a, r.class)
		}
		if c, ok := ClassOf(a); !ok || c != r.class {
			t.Errorf("ClassOf(%s) = %q, %v", a, c, ok)
		}
	}
}
