// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

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
			name:         "web client cannot set the admin password",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: AdminSetPassword},
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
			name:         "web session cannot create a join token",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: ClusterTokenCreate},
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
			name:         "hub cannot remove a hub",
			req:          Request{ActorKind: ActorHub, ActorID: "hub-b", Action: ClusterRemove, Target: "hub-c"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web session cannot remove a hub",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: ClusterRemove, Target: "hub-c"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "join token cannot remove a hub",
			req:          Request{ActorKind: ActorJoinToken, ActorID: "abc", Action: ClusterRemove, Target: "hub-c"},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
		},
		{
			name:         "web session cannot transfer leadership",
			req:          Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: ClusterTransferLeadership},
			wantErr:      ErrDenied,
			wantDecision: Deny,
			wantResult:   "actor kind not allowed",
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
			err = New(s.Audit()).Do(ctx, tt.req, func(context.Context) error {
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

func TestEngineDoAuditFailure(t *testing.T) {
	req := Request{ActorKind: ActorAdmin, ActorID: "root", Action: TokenCreate}
	unavailable := fmt.Errorf("forward: %w", store.ErrUnavailable)
	disk := errors.New("disk full")
	tests := []struct {
		name     string
		runErr   error
		auditErr error
		wantIs   []error
		wantMsg  string
	}{
		{"action ok, audit fails", nil, disk, []error{disk}, "audit token.create: disk full"},
		{
			"same cause reported once", fmt.Errorf("create token: %w", unavailable), unavailable,
			[]error{store.ErrUnavailable},
			"create token: forward: " + store.ErrUnavailable.Error() + " (the audit entry was not written either)",
		},
		{
			"different causes both kept", store.ErrTokenUsed, disk,
			[]error{store.ErrTokenUsed, disk},
			store.ErrTokenUsed.Error() + "\naudit token.create: disk full",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := New(failingAudit{tt.auditErr}).Do(t.Context(), req, func(context.Context) error { return tt.runErr })
			for _, target := range tt.wantIs {
				if !errors.Is(err, target) {
					t.Errorf("err = %v, want it to match %v", err, target)
				}
			}
			if err == nil || err.Error() != tt.wantMsg {
				t.Errorf("message = %q, want %q", err, tt.wantMsg)
			}
		})
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
