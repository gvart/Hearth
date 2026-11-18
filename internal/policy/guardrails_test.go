// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// memAudit is an in-memory Auditor.
type memAudit struct {
	mu      sync.Mutex
	entries []store.AuditEntry
}

func (m *memAudit) Append(_ context.Context, e store.AuditEntry) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return int64(len(m.entries)), nil
}

func (m *memAudit) all() []store.AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.entries)
}

// autoApprovals holds approvals in memory and decides each one with
// decision as soon as it is read.
type autoApprovals struct {
	mu       sync.Mutex
	decision string // approved, denied, or "" to leave them pending
	held     map[string]store.Approval
	created  int
}

func (a *autoApprovals) Create(_ context.Context, ap store.Approval) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.held == nil {
		a.held = map[string]store.Approval{}
	}
	ap.Status = store.ApprovalPending
	a.held[ap.ID] = ap
	a.created++
	return nil
}

func (a *autoApprovals) Get(_ context.Context, id string) (store.Approval, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ap, ok := a.held[id]
	if !ok {
		return store.Approval{}, store.ErrNotFound
	}
	if ap.Status == store.ApprovalPending && a.decision != "" {
		ap.Status, ap.DecidedBy = a.decision, "admin/approver"
		a.held[id] = ap
	}
	return ap, nil
}

func (a *autoApprovals) Decide(_ context.Context, id, status, by string, _ time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ap, ok := a.held[id]
	if !ok {
		return store.ErrNotFound
	}
	if ap.Status != store.ApprovalPending {
		return store.ErrApprovalClosed
	}
	ap.Status, ap.DecidedBy = status, by
	a.held[id] = ap
	return nil
}

// actorKinds are every actor kind there is.
var actorKinds = []string{ActorAdmin, ActorToken, ActorWeb, ActorJoinToken, ActorHub, ActorAutomation, ActorApprovalLink}

// expected is the action table written out independently of rules: its
// class, the actor kinds it admits, and whether the configuration applies.
var expected = map[Action]struct {
	class  Class
	actors []string
	fixed  bool
}{
	TokenCreate:               {Safe, []string{ActorAdmin, ActorWeb}, false},
	DeviceEnroll:              {Safe, []string{ActorToken}, true},
	DeviceRevoke:              {Dangerous, []string{ActorAdmin}, false},
	AdminSetPassword:          {Dangerous, []string{ActorAdmin}, true},
	AdminLogin:                {Safe, []string{ActorWeb}, true},
	ClusterTokenCreate:        {Dangerous, []string{ActorAdmin}, false},
	ClusterJoin:               {Dangerous, []string{ActorJoinToken}, true},
	ClusterPromote:            {Dangerous, []string{ActorHub}, true},
	ClusterRemove:             {Dangerous, []string{ActorAdmin}, false},
	ClusterTransferLeadership: {Safe, []string{ActorAdmin}, false},
	ClusterMigrate:            {Dangerous, []string{ActorAdmin}, false},
	AutomationLog:             {Read, []string{ActorAutomation}, false},
	AutomationWebhook:         {Safe, []string{ActorAutomation}, false},
	AutomationRestart:         {Safe, []string{ActorAutomation}, false},
	AutomationExec:            {Dangerous, []string{ActorAutomation}, false},
	AutomationProbe:           {Read, []string{ActorAutomation}, false},
	KubeClusterAdd:            {Safe, []string{ActorWeb}, false},
	KubeClusterRemove:         {Safe, []string{ActorWeb}, false},
	KubePodLogs:               {Read, []string{ActorWeb}, false},
	KubeWorkloadRestart:       {Safe, []string{ActorWeb, ActorAutomation}, false},
	KubeWorkloadScale:         {Safe, []string{ActorWeb, ActorAutomation}, false},
	KubePodDelete:             {Safe, []string{ActorWeb, ActorAutomation}, false},
	KubeNodeCordon:            {Safe, []string{ActorWeb, ActorAutomation}, false},
	KubeNodeUncordon:          {Safe, []string{ActorWeb, ActorAutomation}, false},
	KubeNodeDrain:             {Dangerous, []string{ActorWeb, ActorAutomation}, false},
	AutomationNotify:          {Safe, []string{ActorAutomation}, false},
	NotifyTest:                {Safe, []string{ActorWeb}, false},
	ApprovalApprove:           {Dangerous, []string{ActorAdmin, ActorWeb, ActorApprovalLink}, true},
	ApprovalDeny:              {Safe, []string{ActorAdmin, ActorWeb, ActorApprovalLink}, true},
}

func TestExpectedCoversEveryAction(t *testing.T) {
	var want []Action
	for a := range expected {
		want = append(want, a)
	}
	slices.Sort(want)
	if got := Actions(); !slices.Equal(got, want) {
		t.Fatalf("Actions() = %v\nthe test table has %v: add the new action to expected", got, want)
	}
}

// uniform sets every class to mode for every configurable actor kind.
func uniform(mode Mode) Config {
	return Config{Classes: map[Class]Mode{Read: mode, Safe: mode, Dangerous: mode}}
}

// TestEveryActionClassActor runs every action, as every actor kind, under
// each configuration mode and the defaults, for real and as a dry run, and
// checks the decision, whether the action ran, and the audit trail.
func TestEveryActionClassActor(t *testing.T) {
	configs := map[string]Config{
		"defaults": {},
		"allow":    uniform(ModeAllow),
		"confirm":  uniform(ModeConfirm),
		"deny":     uniform(ModeDeny),
	}
	for _, action := range Actions() {
		exp := expected[action]
		for _, kind := range actorKinds {
			for cfgName, cfg := range configs {
				for _, dry := range []bool{false, true} {
					name := fmt.Sprintf("%s/%s/%s/%s/dry=%v", action, exp.class, kind, cfgName, dry)
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						checkDecision(t, action, kind, cfgName, cfg, dry)
					})
				}
			}
		}
	}
}

func checkDecision(t *testing.T, action Action, kind, cfgName string, cfg Config, dry bool) {
	exp := expected[action]
	// The decision the rules and the configuration should make.
	want := Allow
	switch {
	case !slices.Contains(exp.actors, kind):
		want = Deny
	case exp.fixed:
	case cfgName == "confirm":
		want = Confirm
	case cfgName == "deny":
		want = Deny
	case cfgName == "defaults" && exp.class == Dangerous && kind == ActorAutomation:
		want = Deny
	}

	audit, approvals := &memAudit{}, &autoApprovals{decision: store.ApprovalApproved}
	e := NewWithConfig(audit, approvals, cfg)
	e.poll = time.Millisecond
	ran := false
	err := e.Do(t.Context(), Request{ActorKind: kind, ActorID: "id", Action: action, Target: "x", DryRun: dry},
		func(context.Context) error { ran = true; return nil })

	if errors.Is(err, ErrDenied) != (want == Deny) {
		t.Fatalf("err = %v, want denied %v", err, want == Deny)
	}
	if want != Deny && err != nil {
		t.Fatalf("err = %v", err)
	}
	wantRan := !dry && want != Deny
	if ran != wantRan {
		t.Fatalf("ran = %v, want %v", ran, wantRan)
	}
	entries := audit.all()
	switch {
	case dry:
		if len(entries) != 1 || entries[0].Decision != want || !strings.HasPrefix(entries[0].Result, DryRun) {
			t.Fatalf("audit = %+v, want one %s dry-run entry", entries, want)
		}
		if approvals.created != 0 {
			t.Fatal("a dry run held an approval")
		}
	case want == Confirm:
		if len(entries) != 2 || entries[0].Decision != Confirm || entries[1].Decision != Allow || entries[1].Result != "ok" {
			t.Fatalf("audit = %+v, want confirm then allow ok", entries)
		}
		if approvals.created != 1 {
			t.Fatalf("held %d approvals, want 1", approvals.created)
		}
	default:
		if len(entries) != 1 || entries[0].Decision != want {
			t.Fatalf("audit = %+v, want one %s entry", entries, want)
		}
		if approvals.created != 0 {
			t.Fatal("an allowed or denied action held an approval")
		}
	}
	if got, _ := e.Check(Request{ActorKind: kind, ActorID: "id", Action: action}); got != want {
		t.Errorf("Check = %s, want %s", got, want)
	}
}

func TestConfigPrecedence(t *testing.T) {
	cfg := Config{
		Classes:              map[Class]Mode{Safe: ModeConfirm, Dangerous: ModeDeny},
		Actors:               map[string]map[Class]Mode{ActorWeb: {Safe: ModeAllow}},
		DangerousAutomations: []string{"trusted"},
	}
	tests := []struct {
		kind, id string
		action   Action
		want     string
	}{
		{ActorWeb, "1.2.3.4", TokenCreate, Allow},                // the actor override wins over the class
		{ActorAdmin, "root", TokenCreate, Confirm},               // the class mode
		{ActorAdmin, "root", DeviceRevoke, Deny},                 // the class mode
		{ActorAutomation, "trusted", AutomationExec, Allow},      // a grant wins over everything
		{ActorAutomation, "other", AutomationExec, Deny},         // the class mode
		{ActorAutomation, "other", AutomationLog, Allow},         // read is not configured
		{ActorAdmin, "root", AdminSetPassword, Allow},            // fixed: never held or denied by config
		{ActorWeb, "1.2.3.4", ApprovalApprove, Allow},            // fixed
		{ActorAutomation, "trusted", ApprovalApprove, Deny},      // a grant is not an actor kind
		{ActorAutomation, "trusted", AutomationWebhook, Confirm}, // grants cover dangerous actions only
	}
	e := NewWithConfig(&memAudit{}, nil, cfg)
	for _, tt := range tests {
		if got, reason := e.Check(Request{ActorKind: tt.kind, ActorID: tt.id, Action: tt.action}); got != tt.want {
			t.Errorf("%s by %s/%s = %s (%s), want %s", tt.action, tt.kind, tt.id, got, reason, tt.want)
		}
	}
	_, reason := NewWithConfig(&memAudit{}, nil, Config{}).Check(Request{ActorKind: ActorAutomation, ActorID: "x", Action: AutomationExec})
	if reason != "dangerous action not granted to this automation" {
		t.Errorf("default automation denial reason = %q", reason)
	}
}

// openStore is a real store, for the confirmation flow end to end.
func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func confirmAll(timeout time.Duration) Config {
	c := uniform(ModeConfirm)
	c.ApprovalTimeout = timeout
	return c
}

func TestConfirmApprovedRuns(t *testing.T) {
	s := openStore(t)
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(time.Minute))
	e.poll = 5 * time.Millisecond
	held := make(chan string, 1)
	ran := false
	done := make(chan error, 1)
	go func() {
		done <- e.Do(t.Context(), Request{
			ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi",
			OnHold: func(id string, _ time.Time) { held <- id },
		}, func(context.Context) error { ran = true; return nil })
	}()
	id := <-held
	if ran {
		t.Fatal("ran before approval")
	}
	if err := e.Decide(t.Context(), ActorWeb, "192.0.2.1", id, true); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || !ran {
		t.Fatalf("Do = %v, ran %v; want approved and run", err, ran)
	}
	// Deciding again is refused.
	if err := e.Decide(t.Context(), ActorAdmin, "root", id, false); !errors.Is(err, store.ErrApprovalClosed) {
		t.Errorf("second decision = %v, want ErrApprovalClosed", err)
	}
	entries, _ := s.Audit().List(t.Context(), 10)
	var trail []string
	for _, en := range slices.Backward(entries) {
		trail = append(trail, en.Action+":"+en.Decision)
	}
	want := []string{"device.revoke:confirm", "approval.approve:allow", "device.revoke:allow", "approval.deny:allow"}
	if !slices.Equal(trail, want) {
		t.Errorf("audit trail = %v, want %v", trail, want)
	}
	if !strings.Contains(string(entries[1].Detail), "web/192.0.2.1") {
		t.Errorf("approved entry detail = %s, want the approver", entries[1].Detail)
	}
}

func TestConfirmNegative(t *testing.T) {
	denyIt := func(t *testing.T, e *Engine, id string) {
		if err := e.Decide(t.Context(), ActorAdmin, "root", id, false); err != nil {
			t.Error(err)
		}
	}
	tests := []struct {
		name       string
		timeout    time.Duration
		cancel     bool
		decide     func(t *testing.T, e *Engine, id string)
		wantResult string
		wantStatus string
	}{
		{
			name: "denied by an operator", timeout: time.Minute, decide: denyIt,
			wantResult: "approval denied by admin/root", wantStatus: store.ApprovalDenied,
		},
		{
			name: "expires unapproved", timeout: 50 * time.Millisecond,
			wantResult: "approval expired", wantStatus: store.ApprovalExpired,
		},
		{
			name: "requester gives up", timeout: time.Minute, cancel: true,
			wantResult: "approval cancelled", wantStatus: store.ApprovalExpired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(tt.timeout))
			e.poll = 5 * time.Millisecond
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var id string
			ran := false
			err := e.Do(ctx, Request{
				ActorKind: ActorAutomation, ActorID: "a", Action: AutomationExec, Target: "pi",
				OnHold: func(held string, _ time.Time) {
					id = held
					switch {
					case tt.cancel:
						cancel()
					case tt.decide != nil:
						go tt.decide(t, e, held)
					}
				},
			}, func(context.Context) error { ran = true; return nil })
			if !errors.Is(err, ErrDenied) || ran {
				t.Fatalf("Do = %v, ran %v; want denied, not run", err, ran)
			}
			entries, _ := s.Audit().List(t.Context(), 10)
			last := entries[0]
			if last.Action != string(AutomationExec) || last.Decision != Deny || !strings.HasPrefix(last.Result, tt.wantResult) {
				t.Errorf("final audit = %+v, want deny %q", last, tt.wantResult)
			}
			ap, err := s.Approvals().Get(t.Context(), id)
			if err != nil || ap.Status != tt.wantStatus {
				t.Errorf("approval = %+v, %v; want %s", ap, err, tt.wantStatus)
			}
			// An expired or decided approval can no longer be approved.
			if err := e.Decide(t.Context(), ActorAdmin, "root", id, true); !errors.Is(err, store.ErrApprovalClosed) {
				t.Errorf("late approval = %v, want ErrApprovalClosed", err)
			}
		})
	}
}

// failingApprovals cannot hold anything, like a cluster before the
// approvals schema.
type failingApprovals struct{ autoApprovals }

func (*failingApprovals) Create(context.Context, store.Approval) error { return store.ErrSchemaTooOld }

func TestConfirmWithoutApprovalsIsDenied(t *testing.T) {
	for name, approvals := range map[string]Approvals{"none": nil, "cannot hold": &failingApprovals{}} {
		t.Run(name, func(t *testing.T) {
			audit := &memAudit{}
			ran := false
			err := NewWithConfig(audit, approvals, uniform(ModeConfirm)).Do(t.Context(),
				Request{ActorKind: ActorAdmin, ActorID: "root", Action: TokenCreate},
				func(context.Context) error { ran = true; return nil })
			if !errors.Is(err, ErrDenied) || ran {
				t.Fatalf("Do = %v, ran %v; want denied", err, ran)
			}
			if e := audit.all(); len(e) != 1 || e[0].Decision != Deny || !strings.Contains(e[0].Result, "needs approval") {
				t.Errorf("audit = %+v", e)
			}
		})
	}
}

func TestPrecheck(t *testing.T) {
	beyond := fmt.Errorf("exec /bin/sh: %w", ErrBeyondCeiling)
	tests := []struct {
		name     string
		cfg      Config
		dry      bool
		check    error
		wantDeny bool
		wantRan  bool
	}{
		{"beyond the ceiling is denied", uniform(ModeAllow), false, beyond, true, false},
		{"beyond the ceiling is never held", uniform(ModeConfirm), false, beyond, true, false},
		{"beyond the ceiling, dry run", uniform(ModeAllow), true, beyond, true, false},
		{"other errors are left to the action", uniform(ModeAllow), false, errors.New("agent not connected"), false, true},
		{"within the ceiling", uniform(ModeAllow), false, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audit, approvals := &memAudit{}, &autoApprovals{decision: store.ApprovalApproved}
			e := NewWithConfig(audit, approvals, tt.cfg)
			ran := false
			err := e.Do(t.Context(), Request{
				ActorKind: ActorAutomation, ActorID: "a", Action: AutomationRestart, DryRun: tt.dry,
				Precheck: func(context.Context) error { return tt.check },
			}, func(context.Context) error { ran = true; return nil })
			if errors.Is(err, ErrDenied) != tt.wantDeny || ran != tt.wantRan {
				t.Fatalf("Do = %v, ran %v", err, ran)
			}
			if tt.wantDeny {
				if e := audit.all(); len(e) != 1 || e[0].Decision != Deny || !strings.Contains(e[0].Result, "capability ceiling") {
					t.Errorf("audit = %+v", e)
				}
				if approvals.created != 0 {
					t.Error("held an action beyond the ceiling")
				}
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "policy.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if c, err := LoadConfig(filepath.Join(dir, "missing.yaml")); err != nil || c.Classes != nil {
		t.Fatalf("missing file = %+v, %v; want the zero config", c, err)
	}
	c, err := LoadConfig(write(`
classes: {dangerous: confirm}
actors:
  automation: {safe: deny}
dangerous_automations: [backup]
approval_timeout: 5m
approval_notify: {channel: phone, url: "https://hearth.lan:8443"}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Classes[Dangerous] != ModeConfirm || c.Actors[ActorAutomation][Safe] != ModeDeny ||
		!slices.Equal(c.DangerousAutomations, []string{"backup"}) || c.ApprovalTimeout != 5*time.Minute ||
		c.ApprovalNotify != (ApprovalNotify{Channel: "phone", URL: "https://hearth.lan:8443"}) {
		t.Errorf("config = %+v", c)
	}
	if _, err := LoadConfig(write("")); err != nil {
		t.Errorf("empty file: %v", err)
	}
	for name, body := range map[string]string{
		"unknown field":         "class: {safe: allow}",
		"unknown class":         "classes: {risky: allow}",
		"unknown mode":          "classes: {safe: maybe}",
		"machine actor kind":    "actors: {token: {safe: deny}}",
		"unknown actor kind":    "actors: {mcp: {safe: deny}}",
		"actor with a bad mode": "actors: {web: {safe: ask}}",
		"negative timeout":      "approval_timeout: -1m",
		"notify url scheme":     "approval_notify: {channel: phone, url: ftp://hub}",
		"notify url no host":    "approval_notify: {channel: phone, url: https://}",
		"notify url query":      "approval_notify: {channel: phone, url: 'https://hub/?t=1'}",
		"notify url userinfo":   "approval_notify: {channel: phone, url: 'https://u:p@hub'}",
		"notify url no channel": "approval_notify: {url: https://hub}",
		"notify unknown key":    "approval_notify: {channel: phone, topic: x}",
	} {
		if _, err := LoadConfig(write(body)); err == nil {
			t.Errorf("%s: loaded, want an error", name)
		}
	}
}
