// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/gvart/hearth/internal/store"
)

type memAudit struct{ entries []store.AuditEntry }

func (m *memAudit) Append(_ context.Context, e store.AuditEntry) (int64, error) {
	m.entries = append(m.entries, e)
	return int64(len(m.entries)), nil
}

func TestNotifyActions(t *testing.T) {
	tests := []struct {
		name      string
		req       Request
		wantClass Class
		wantDeny  string
	}{
		{"automation notifies", Request{ActorKind: ActorAutomation, ActorID: "a", Action: AutomationNotify, Target: "phone"}, Safe, ""},
		{
			"web cannot run an automation's notify",
			Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: AutomationNotify, Target: "phone"},
			Safe, "actor kind not allowed",
		},
		{"web sends a test", Request{ActorKind: ActorWeb, ActorID: "192.0.2.1", Action: NotifyTest, Target: "phone"}, Safe, ""},
		{
			"automation cannot send a test",
			Request{ActorKind: ActorAutomation, ActorID: "a", Action: NotifyTest, Target: "phone"},
			Safe, "actor kind not allowed",
		},
		{"anonymous web test denied", Request{ActorKind: ActorWeb, Action: NotifyTest, Target: "phone"}, Safe, "anonymous actor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if c, ok := ClassOf(tt.req.Action); !ok || c != tt.wantClass {
				t.Fatalf("class = %q, %v", c, ok)
			}
			audit := &memAudit{}
			ran := false
			err := New(audit).Do(t.Context(), tt.req, func(context.Context) error { ran = true; return nil })
			if len(audit.entries) != 1 {
				t.Fatalf("audit entries = %d", len(audit.entries))
			}
			e := audit.entries[0]
			if tt.wantDeny == "" {
				if err != nil || !ran || e.Decision != Allow {
					t.Errorf("err %v ran %v entry %+v, want allowed", err, ran, e)
				}
				return
			}
			if !errors.Is(err, ErrDenied) || ran || e.Decision != Deny || e.Result != tt.wantDeny {
				t.Errorf("err %v ran %v entry %+v, want denied: %s", err, ran, e, tt.wantDeny)
			}
		})
	}
}
