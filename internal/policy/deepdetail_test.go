// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// deepDetail returns a detail nested far beyond what the audit log stores.
func deepDetail() map[string]any {
	var v any = "leaf"
	for range 100 {
		v = map[string]any{"n": v}
	}
	return map[string]any{"deep": v}
}

func openDeepStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestOverDeepDetailKeepsItsEntry: a detail the audit log would refuse must
// never cost an action its entry, change its decision or its error, nor keep
// it from running.
func TestOverDeepDetailKeepsItsEntry(t *testing.T) {
	admin := Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi"}
	with := func(f func(*Request)) func() Request {
		return func() Request {
			r := admin
			r.Detail = deepDetail()
			f(&r)
			return r
		}
	}
	growing := func() Request {
		r := admin
		r.Detail = map[string]any{}
		return r
	}
	tests := []struct {
		name       string
		cfg        Config
		approval   string // decision of the approvals, when the request is held
		req        func() Request
		grow       bool // the detail grows too deep while the action runs
		wantDenied bool
		wantRan    bool
		wantResult string // prefix of the result of the one row the log shows
		wantTag    string // decision of that row
	}{
		{"denied", Config{}, "", with(func(r *Request) { r.ActorKind = "nobody" }),
			false, true, false, "actor kind not allowed", Deny},
		{"denied by the configuration", uniform(ModeDeny), "", with(func(*Request) {}),
			false, true, false, "dangerous actions by admin are denied", Deny},
		{"dry run", Config{}, "", with(func(r *Request) { r.DryRun = true }),
			false, false, false, DryRun, Allow},
		{"dry run of a denied request", Config{}, "", with(func(r *Request) { r.DryRun = true; r.ActorKind = "nobody" }),
			false, true, false, DryRun, Deny},
		{"allowed", Config{}, "", with(func(*Request) {}),
			false, false, true, "ok", Allow},
		{"allowed, detail grows during the action", Config{}, "", growing,
			true, false, true, "ok", Allow},
		{"held and approved", uniform(ModeConfirm), store.ApprovalApproved, with(func(*Request) {}),
			false, false, true, "ok", Allow},
		{"held and approved, detail grows during the action", uniform(ModeConfirm), store.ApprovalApproved, growing,
			true, false, true, "ok", Allow},
		{"held and denied", uniform(ModeConfirm), store.ApprovalDenied, with(func(*Request) {}),
			false, true, false, "approval denied", Deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openDeepStore(t)
			var approvals Approvals
			if tt.approval != "" {
				approvals = &autoApprovals{decision: tt.approval}
			}
			e := NewWithConfig(s.Audit(), approvals, tt.cfg)
			e.poll = time.Millisecond
			req := tt.req()
			ran := false
			err := e.Do(t.Context(), req, func(context.Context) error {
				ran = true
				if tt.grow {
					for k, v := range deepDetail() {
						req.Detail[k] = v
					}
				}
				return nil
			})
			if errors.Is(err, ErrDenied) != tt.wantDenied {
				t.Errorf("Do = %v, want denied %v", err, tt.wantDenied)
			}
			if !tt.wantDenied && err != nil {
				t.Errorf("Do = %v, want success", err)
			}
			if ran != tt.wantRan {
				t.Errorf("action ran = %v, want %v", ran, tt.wantRan)
			}
			rows, err := s.Audit().List(t.Context(), 20)
			if err != nil {
				t.Fatal(err)
			}
			// A held request has its hold and then its end; the others have one row.
			want := 1
			if tt.approval != "" {
				want = 2
			}
			if len(rows) != want {
				t.Fatalf("audit = %+v, want %d rows", rows, want)
			}
			last := rows[0]
			if last.Decision != tt.wantTag || !strings.HasPrefix(last.Result, tt.wantResult) {
				t.Errorf("last row = %s %q, want %s %q", last.Decision, last.Result, tt.wantTag, tt.wantResult)
			}
			var d map[string]any
			if err := json.Unmarshal(last.Detail, &d); err != nil {
				t.Fatalf("detail %s: %v", last.Detail, err)
			}
			if _, ok := d[DetailOmitted]; !ok {
				t.Errorf("detail = %s, want the placeholder (%s)", last.Detail, DetailOmitted)
			}
			if _, ok := d["deep"]; ok {
				t.Errorf("detail = %s, want the deep part dropped", last.Detail)
			}
			for _, k := range []string{store.AuditOpKey, store.AuditOutcomeOfKey} {
				if _, ok := d[k]; ok {
					t.Errorf("detail = %s, tie key %s leaked", last.Detail, k)
				}
			}
		})
	}
}

// TestOverDeepDetailStartedEntryIsWritten: the entry written before an
// allowed action runs exists, with the placeholder, when the action starts.
func TestOverDeepDetailStartedEntryIsWritten(t *testing.T) {
	s := openDeepStore(t)
	req := Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi", Detail: deepDetail()}
	err := New(s.Audit()).Do(t.Context(), req, func(ctx context.Context) error {
		rows, err := s.Audit().List(ctx, 10)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Result != Started || !strings.Contains(string(rows[0].Detail), DetailOmitted) {
			t.Errorf("audit during the action = %+v, want one started row with the placeholder", rows)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
