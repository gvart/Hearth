// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// TestScope checks that a credential's scope caps what its requests may do,
// whatever the configuration allows, and that a request beyond it is denied
// and audited without being held or run.
func TestScope(t *testing.T) {
	tests := []struct {
		scope    Class
		action   Action
		wantDeny bool
	}{
		{Read, DeviceRead, false},
		{Read, DeviceRestart, true},
		{Read, DeviceExec, true},
		{Safe, DeviceRestart, false},
		{Safe, DeviceExec, true},
		{Safe, KubeNodeDrain, true},
		{Dangerous, DeviceExec, false},
		{"bogus", DeviceRead, true},
	}
	for _, tt := range tests {
		for _, dry := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/dry=%v", tt.scope, tt.action, dry), func(t *testing.T) {
				audit, approvals := &memAudit{}, &autoApprovals{decision: store.ApprovalApproved}
				e := NewWithConfig(audit, approvals, uniform(ModeAllow))
				ran := false
				err := e.Do(WithScope(t.Context(), tt.scope), Request{
					ActorKind: ActorMCP, ActorID: "claude", Action: tt.action, DryRun: dry,
				}, func(context.Context) error { ran = true; return nil })
				if errors.Is(err, ErrDenied) != tt.wantDeny {
					t.Fatalf("Do = %v, want denied %v", err, tt.wantDeny)
				}
				if ran != (!tt.wantDeny && !dry) {
					t.Errorf("ran = %v", ran)
				}
				entries := audit.all()
				if len(entries) != 1 || entries[0].ActorKind != ActorMCP || entries[0].ActorID != "claude" {
					t.Fatalf("audit = %+v", entries)
				}
				if tt.wantDeny && (entries[0].Decision != Deny || !strings.Contains(entries[0].Result, "scope")) {
					t.Errorf("audit = %+v", entries[0])
				}
				if approvals.created != 0 {
					t.Error("held a request")
				}
			})
		}
	}
}

// TestMCPDangerousConfirmsByDefault checks that, with no configuration, a
// dangerous MCP request is held for approval, and that the configuration
// can deny it instead.
func TestMCPDangerousConfirmsByDefault(t *testing.T) {
	for name, tt := range map[string]struct {
		cfg      Config
		wantHeld bool
	}{
		"defaults":   {Config{}, true},
		"mcp denied": {Config{Actors: map[string]map[Class]Mode{ActorMCP: {Dangerous: ModeDeny}}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			audit, approvals := &memAudit{}, &autoApprovals{decision: store.ApprovalApproved}
			e := NewWithConfig(audit, approvals, tt.cfg)
			e.poll = time.Millisecond
			ran := false
			err := e.Do(WithScope(t.Context(), Dangerous), Request{ActorKind: ActorMCP, ActorID: "claude", Action: DeviceExec},
				func(context.Context) error { ran = true; return nil })
			if (approvals.created == 1) != tt.wantHeld || ran != tt.wantHeld || (err == nil) != tt.wantHeld {
				t.Fatalf("held %d, ran %v, err %v", approvals.created, ran, err)
			}
		})
	}
}
