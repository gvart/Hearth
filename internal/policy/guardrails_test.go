// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
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

// raw returns the entries as they were written.
func (m *memAudit) raw() []store.AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.entries)
}

// all returns the entries as store.Audit.Query shows them: one per action.
func (m *memAudit) all() []store.AuditEntry {
	var out []store.AuditEntry
	started := map[string]int{}
	for _, e := range m.raw() {
		var d map[string]any
		_ = json.Unmarshal(e.Detail, &d)
		if op, ok := d[store.AuditOutcomeOfKey].(string); ok {
			if i, ok := started[op]; ok {
				out[i].Result, out[i].Detail = e.Result, e.Detail
				continue
			}
		}
		if op, ok := d[store.AuditOpKey].(string); ok {
			started[op] = len(out)
		}
		out = append(out, e)
	}
	return out
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

func (a *autoApprovals) Overdue(context.Context, time.Time, int) ([]store.Approval, error) {
	return nil, nil
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
var actorKinds = []string{ActorAdmin, ActorToken, ActorWeb, ActorJoinToken, ActorHub, ActorAutomation, ActorApprovalLink, ActorMCP, ActorGuest, ActorDashboard}

// expected is the action table written out independently of rules: its
// class, the actor kinds it admits, and whether the configuration applies.
var expected = map[Action]struct {
	class  Class
	actors []string
	fixed  bool
}{
	TokenCreate:               {Safe, []string{ActorAdmin, ActorWeb}, false},
	DeviceEnroll:              {Safe, []string{ActorToken}, true},
	DeviceRevoke:              {Dangerous, []string{ActorAdmin, ActorWeb}, false},
	AdminSetPassword:          {Dangerous, []string{ActorAdmin, ActorWeb}, false},
	AdminLogin:                {Safe, []string{ActorWeb}, true},
	AdminReauth:               {Safe, []string{ActorWeb}, true},
	ClusterTokenCreate:        {Dangerous, []string{ActorAdmin}, false},
	ClusterJoin:               {Dangerous, []string{ActorJoinToken}, true},
	ClusterPromote:            {Dangerous, []string{ActorHub, ActorAdmin, ActorWeb}, false},
	ClusterDemote:             {Dangerous, []string{ActorAdmin, ActorWeb}, false},
	ClusterRemove:             {Dangerous, []string{ActorAdmin, ActorWeb}, false},
	ClusterTransferLeadership: {Safe, []string{ActorAdmin}, false},
	ClusterMigrate:            {Dangerous, []string{ActorAdmin}, false},
	ClusterCARotate:           {Dangerous, []string{ActorAdmin}, false},
	ClusterCAFinish:           {Dangerous, []string{ActorAdmin}, false},
	ClusterCAAbort:            {Dangerous, []string{ActorAdmin}, false},
	ClusterCAFetchKey:         {Dangerous, []string{ActorHub}, true},
	AutomationLog:             {Read, []string{ActorAutomation}, false},
	AutomationWebhook:         {Safe, []string{ActorAutomation}, false},
	AutomationRestart:         {Safe, []string{ActorAutomation}, false},
	AutomationExec:            {Dangerous, []string{ActorAutomation}, false},
	AutomationProbe:           {Read, []string{ActorAutomation}, false},
	KubeClusterAdd:            {Safe, []string{ActorWeb}, false},
	KubeClusterRemove:         {Safe, []string{ActorWeb}, false},
	KubePodLogs:               {Read, []string{ActorWeb, ActorMCP}, false},
	KubeWorkloadRestart:       {Safe, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
	KubeWorkloadScale:         {Safe, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
	KubePodDelete:             {Safe, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
	KubeNodeCordon:            {Safe, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
	KubeNodeUncordon:          {Safe, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
	KubeNodeDrain:             {Dangerous, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
	KubeNodeDelete:            {Dangerous, []string{ActorAutomation}, false},
	KubeNodeReady:             {Read, []string{ActorAutomation}, false},
	AutomationNotify:          {Safe, []string{ActorAutomation}, false},
	AutomationScript:          {Safe, []string{ActorAutomation}, false},
	NotifyTest:                {Safe, []string{ActorWeb}, false},
	ApprovalApprove:           {Dangerous, []string{ActorAdmin, ActorWeb, ActorApprovalLink}, true},
	ApprovalDeny:              {Safe, []string{ActorAdmin, ActorWeb, ActorApprovalLink}, true},
	DeviceRead:                {Read, []string{ActorMCP, ActorAutomation}, false},
	DeviceMetrics:             {Read, []string{ActorMCP}, false},
	DeviceLogs:                {Read, []string{ActorWeb}, false},
	DeviceNetEdges:            {Read, []string{ActorWeb}, false},
	NetworkTopology:           {Read, []string{ActorWeb}, false},
	DeviceDockerList:          {Read, []string{ActorWeb}, false},
	DeviceDockerLogs:          {Read, []string{ActorWeb}, false},
	DeviceDockerStart:         {Safe, []string{ActorWeb}, false},
	DeviceDockerStop:          {Safe, []string{ActorWeb}, false},
	DeviceDockerRestart:       {Safe, []string{ActorWeb}, false},
	KubeRead:                  {Read, []string{ActorMCP}, false},
	DeviceRestart:             {Safe, []string{ActorMCP, ActorGuest}, false},
	DeviceExec:                {Dangerous, []string{ActorMCP}, false},
	AutomationPlan:            {Read, []string{ActorMCP}, false},
	AutomationApply:           {Dangerous, []string{ActorMCP, ActorWeb}, false},
	MCPTokenCreate:            {Dangerous, []string{ActorAdmin, ActorWeb}, false},
	MCPTokenRevoke:            {Safe, []string{ActorAdmin, ActorWeb}, false},
	NetworkScan:               {Read, []string{ActorHub}, false},
	NetworkHostMark:           {Safe, []string{ActorWeb}, false},
	NetworkImport:             {Read, []string{ActorHub}, false},
	BeszelRead:                {Read, []string{ActorHub}, false},
	TalosRead:                 {Read, []string{ActorHub, ActorAutomation}, false},
	ProxmoxServerAdd:          {Safe, []string{ActorWeb}, false},
	ProxmoxServerRemove:       {Safe, []string{ActorWeb}, false},
	ProxmoxGuestStart:         {Safe, []string{ActorWeb}, false},
	ProxmoxGuestStop:          {Dangerous, []string{ActorWeb}, false},
	ProxmoxGuestReboot:        {Dangerous, []string{ActorWeb}, false},
	RunbookStart:              {Safe, []string{ActorWeb}, false},
	RunbookAnswer:             {Safe, []string{ActorWeb}, true},
	RunbookRetry:              {Safe, []string{ActorWeb}, false},
	RunbookRollback:           {Safe, []string{ActorWeb}, false},
	RunbookPassOver:           {Safe, []string{ActorWeb}, false},
	RunbookCheck:              {Read, []string{ActorAutomation}, false},
	HubBackup:                 {Dangerous, []string{ActorAdmin, ActorWeb}, false},
	HubRestore:                {Dangerous, []string{ActorAdmin}, true},
	HubScheduledBackup:        {Dangerous, []string{ActorHub}, true},
	ConfigImport:              {Dangerous, []string{ActorAdmin, ActorWeb}, false},
	ConfigImportFirst:         {Dangerous, []string{ActorHub}, true},
	ConfigExport:              {Read, []string{ActorAdmin}, false},
	TelemetrySet:              {Safe, []string{ActorWeb}, false},
	DeviceShell:               {Dangerous, []string{ActorWeb}, false},
	PanelSave:                 {Safe, []string{ActorWeb}, false},
	PanelDelete:               {Safe, []string{ActorWeb}, false},
	PanelLinkCreate:           {Safe, []string{ActorWeb}, false},
	PanelLinkRevoke:           {Safe, []string{ActorWeb}, false},
	DashboardRead:             {Read, []string{ActorDashboard}, false},
	DashboardTokenCreate:      {Safe, []string{ActorWeb}, false},
	DashboardTokenRevoke:      {Safe, []string{ActorWeb}, false},
	PluginStart:               {Dangerous, []string{ActorHub}, true},
	PluginCommandRead:         {Read, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
	PluginCommandSafe:         {Safe, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
	PluginCommandDangerous:    {Dangerous, []string{ActorWeb, ActorAutomation, ActorMCP}, false},
}

// fixedFor are the actor kinds for which an action that is not fixed for
// every one ignores the configuration.
var fixedFor = map[Action][]string{
	// A Raft voter promoting itself, in the join protocol; an admin's
	// promotion in an AP cluster is held or denied as configured.
	ClusterPromote: {ActorHub},
	// The hub host's set-password is the way back in, never held; the web
	// UI's change follows the modes.
	AdminSetPassword: {ActorAdmin},
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
	case exp.fixed, slices.Contains(fixedFor[action], kind):
	case cfgName == "confirm":
		want = Confirm
	case cfgName == "deny":
		want = Deny
	case cfgName == "defaults" && exp.class == Dangerous && kind == ActorAutomation:
		want = Deny
	case cfgName == "defaults" && exp.class == Dangerous && kind == ActorMCP:
		want = Confirm
	case cfgName == "defaults" && exp.class == Dangerous && kind == ActorGuest:
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

// TestAuditedAfterRequesterLeft cancels the request while the action runs:
// what ran is in the audit log all the same.
func TestAuditedAfterRequesterLeft(t *testing.T) {
	s := openStore(t)
	e := New(s.Audit())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := e.Do(ctx, Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi"},
		func(context.Context) error {
			cancel()
			return nil
		})
	if err != nil {
		t.Fatalf("Do = %v", err)
	}
	entries, err := s.Audit().List(t.Context(), 10)
	if err != nil || len(entries) != 1 || entries[0].Decision != Allow {
		t.Fatalf("audit = %v, %v; want the action allowed", entries, err)
	}
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
	if err := e.Decide(t.Context(), ActorWeb, "192.0.2.1", id, true, reauthed); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || !ran {
		t.Fatalf("Do = %v, ran %v; want approved and run", err, ran)
	}
	// Deciding again is refused.
	if err := e.Decide(t.Context(), ActorAdmin, "root", id, false, nil); !errors.Is(err, store.ErrApprovalClosed) {
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
		if err := e.Decide(t.Context(), ActorAdmin, "root", id, false, nil); err != nil {
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
			var deciding sync.WaitGroup
			ran := false
			err := e.Do(ctx, Request{
				ActorKind: ActorAutomation, ActorID: "a", Action: AutomationExec, Target: "pi",
				OnHold: func(held string, _ time.Time) {
					id = held
					switch {
					case tt.cancel:
						cancel()
					case tt.decide != nil:
						deciding.Go(func() { tt.decide(t, e, held) })
					}
				},
			}, func(context.Context) error { ran = true; return nil })
			deciding.Wait()
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
			if err := e.Decide(t.Context(), ActorAdmin, "root", id, true, reauthed); !errors.Is(err, store.ErrApprovalClosed) {
				t.Errorf("late approval = %v, want ErrApprovalClosed", err)
			}
		})
	}
}

// decisionLog is an approvals store that records the audit trail as it stood
// when each decision took effect, which is when a held request can see it.
type decisionLog struct {
	autoApprovals
	audit     *memAudit
	decideErr error
	atDecide  []store.AuditEntry
}

func (d *decisionLog) Decide(ctx context.Context, id, status, by string, at time.Time) error {
	d.atDecide = d.audit.all()
	if d.decideErr != nil {
		return d.decideErr
	}
	return d.autoApprovals.Decide(ctx, id, status, by, at)
}

// heldApproval stores one pending approval in d and returns its id.
func heldApproval(t *testing.T, d *decisionLog) string {
	t.Helper()
	ap := store.Approval{ID: "ap", ActorKind: ActorAutomation, ActorID: "a", Action: string(AutomationExec), ExpiresAt: time.Now().Add(time.Minute)}
	if err := d.Create(t.Context(), ap); err != nil {
		t.Fatal(err)
	}
	return ap.ID
}

// TestDecisionAuditedBeforeItTakesEffect: a held request runs as soon as it
// can read its approval's decision, so the decision must be in the audit log
// by then. Otherwise the log shows the action before the approval allowing it.
func TestDecisionAuditedBeforeItTakesEffect(t *testing.T) {
	for name, tt := range map[string]struct {
		approve bool
		action  Action
	}{
		"approve": {true, ApprovalApprove},
		"deny":    {false, ApprovalDeny},
	} {
		t.Run(name, func(t *testing.T) {
			audit := &memAudit{}
			approvals := &decisionLog{audit: audit}
			id := heldApproval(t, approvals)
			e := NewWithConfig(audit, approvals, Config{})
			if err := e.Decide(t.Context(), ActorWeb, "192.0.2.1", id, tt.approve, reauthed); err != nil {
				t.Fatal(err)
			}
			if got := approvals.atDecide; len(got) != 1 || got[0].Action != string(tt.action) || got[0].Decision != Allow || got[0].Result != Started {
				t.Errorf("audit when the decision took effect = %+v, want the %s entry", got, tt.action)
			}
			if got := audit.all(); len(got) != 1 {
				t.Errorf("audit = %+v, want one entry", got)
			}
		})
	}
}

// TestDecisionNotAuditedDoesNotTakeEffect: deny by default, a decision that
// cannot be audited is not made.
func TestDecisionNotAuditedDoesNotTakeEffect(t *testing.T) {
	approvals := &decisionLog{audit: &memAudit{}}
	id := heldApproval(t, approvals)
	e := NewWithConfig(failingAudit{errors.New("audit log unavailable")}, approvals, Config{})
	if err := e.Decide(t.Context(), ActorWeb, "192.0.2.1", id, true, reauthed); err == nil {
		t.Fatal("Decide succeeded without an audit entry")
	}
	ap, err := approvals.Get(t.Context(), id)
	if err != nil || ap.Status != store.ApprovalPending {
		t.Errorf("approval = %+v, %v; want it still pending", ap, err)
	}
}

// TestDecisionLostRaceIsAudited: a decision that loses to another one after
// it was audited ends with an outcome saying it failed.
func TestDecisionLostRaceIsAudited(t *testing.T) {
	audit := &memAudit{}
	approvals := &decisionLog{audit: audit, decideErr: store.ErrApprovalClosed}
	id := heldApproval(t, approvals)
	e := NewWithConfig(audit, approvals, Config{})
	if err := e.Decide(t.Context(), ActorWeb, "192.0.2.1", id, true, reauthed); !errors.Is(err, store.ErrApprovalClosed) {
		t.Fatalf("Decide = %v, want ErrApprovalClosed", err)
	}
	got := audit.all()
	if len(got) != 1 || !strings.HasPrefix(got[0].Result, "error: ") {
		t.Errorf("audit = %+v, want the decision showing its failure", got)
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
	if _, err := LoadConfig(write("actors: {guest: {safe: confirm, dangerous: deny}}")); err != nil {
		t.Errorf("guest with dangerous deny: %v", err)
	}
	for name, body := range map[string]string{
		"unknown field":         "class: {safe: allow}",
		"unknown class":         "classes: {risky: allow}",
		"unknown mode":          "classes: {safe: maybe}",
		"machine actor kind":    "actors: {token: {safe: deny}}",
		"unknown actor kind":    "actors: {robot: {safe: deny}}",
		"actor with a bad mode": "actors: {web: {safe: ask}}",
		"dangerous guest allow": "actors: {guest: {dangerous: allow}}",
		"dangerous guest hold":  "actors: {guest: {dangerous: confirm}}",
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

// TestGuestNeverDangerous: a panel's guest holds an unauthenticated link, so
// no rule may admit it to a dangerous action.
func TestGuestNeverDangerous(t *testing.T) {
	for _, a := range Actions() {
		class, _ := ClassOf(a)
		if Admits(a, ActorGuest) && class == Dangerous {
			t.Errorf("%s is dangerous and admits %s", a, ActorGuest)
		}
	}
	if !Admits(DeviceRestart, ActorGuest) || Admits(DeviceExec, ActorGuest) || Admits("no.such", ActorGuest) {
		t.Error("Admits disagrees with the rule table")
	}
}

// TestGuestConfigurable: an operator can hold or refuse guests' actions.
func TestGuestConfigurable(t *testing.T) {
	for _, tt := range []struct {
		mode Mode
		want string
	}{{ModeAllow, Allow}, {ModeConfirm, Confirm}, {ModeDeny, Deny}} {
		cfg := Config{Actors: map[string]map[Class]Mode{ActorGuest: {Safe: tt.mode}}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		e := NewWithConfig(&memAudit{}, nil, cfg)
		if got, _ := e.Check(Request{ActorKind: ActorGuest, ActorID: "panel/p1", Action: DeviceRestart}); got != tt.want {
			t.Errorf("guest safe %s: decision = %s, want %s", tt.mode, got, tt.want)
		}
	}
}

// TestDashboardOnlyReads: a dashboard token reads the dashboard summary and
// nothing else, so no other rule may admit the dashboard actor.
func TestDashboardOnlyReads(t *testing.T) {
	for _, a := range Actions() {
		if Admits(a, ActorDashboard) && a != DashboardRead {
			t.Errorf("%s admits %s", a, ActorDashboard)
		}
	}
	if class, _ := ClassOf(DashboardRead); class != Read || !Admits(DashboardRead, ActorDashboard) {
		t.Errorf("dashboard.read is %s, want read and admitting %s", class, ActorDashboard)
	}
	// An operator can turn dashboards off.
	cfg := Config{Actors: map[string]map[Class]Mode{ActorDashboard: {Read: ModeDeny}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	e := NewWithConfig(&memAudit{}, nil, cfg)
	if got, _ := e.Check(Request{ActorKind: ActorDashboard, ActorID: "token/t1", Action: DashboardRead}); got != Deny {
		t.Errorf("dashboard read with read: deny = %s, want deny", got)
	}
}
