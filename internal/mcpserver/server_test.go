// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// fakeAgents records the requests sent to devices. check, if set, is what
// Check answers.
type fakeAgents struct {
	mu    sync.Mutex
	sent  []*agentv1.ExecRequest
	check error
}

func (a *fakeAgents) Check(context.Context, string, *agentv1.ExecRequest) error { return a.check }

func (a *fakeAgents) Exec(_ context.Context, _ string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sent = append(a.sent, req)
	return &agentv1.ExecResult{Id: "x"}, nil
}

func (a *fakeAgents) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sent)
}

// fakeKube decides each action through policy, as the manager does, and
// records the ones that ran.
type fakeKube struct {
	pol *policy.Engine
	mu  sync.Mutex
	ran []string
}

func (k *fakeKube) Clusters() []kubernetes.ClusterInfo {
	return []kubernetes.ClusterInfo{{ID: "k1", Name: "lab"}}
}

func (k *fakeKube) Snapshot(context.Context, string) (kubernetes.Snapshot, error) {
	return kubernetes.Snapshot{Pods: []kubernetes.Pod{
		{Namespace: "default", Name: "web-1", Status: "Running"},
		{Namespace: "kube-system", Name: "coredns-1", Status: "Running"},
	}}, nil
}

func (k *fakeKube) Logs(ctx context.Context, kind, actor, _, ns, pod, _ string, _ int) (string, error) {
	err := k.pol.Do(ctx, policy.Request{ActorKind: kind, ActorID: actor, Action: policy.KubePodLogs, Target: ns + "/" + pod},
		func(context.Context) error { return nil })
	return "line 1\n", err
}

func (k *fakeKube) Act(ctx context.Context, kind, actor, _ string, req kubernetes.ActionRequest) (kubernetes.ActionResult, error) {
	action := policy.KubeWorkloadRestart
	if req.Action == kubernetes.ActionDrain {
		action = policy.KubeNodeDrain
	}
	err := k.pol.Do(ctx, policy.Request{ActorKind: kind, ActorID: actor, Action: action, Target: req.Name},
		func(context.Context) error {
			k.mu.Lock()
			k.ran = append(k.ran, req.Action)
			k.mu.Unlock()
			return nil
		})
	return kubernetes.ActionResult{Action: req.Action}, err
}

type fixture struct {
	st     *store.Store
	pol    *policy.Engine
	agents *fakeAgents
	kube   *fakeKube
	dir    string
	url    string
}

// newFixture serves MCP over a store with one device and the tokens
// read-token (read), safe-token (safe), dangerous-token (dangerous) and
// revoked-token (safe, revoked).
func newFixture(t *testing.T, cfg policy.Config, opts ...func(*Config)) *fixture {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now()
	if err := st.Devices().Upsert(ctx, store.Device{
		ID: "dev-1", Name: "pi", Hostname: "pi.lan", OS: "linux", Arch: "arm64", Status: store.StatusOnline,
		Labels: map[string]string{"room": "attic"}, FirstSeen: now, LastSeen: now, Facts: []byte(`{"cpus":4}`),
	}); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []struct{ name, scope string }{
		{"reader", "read"}, {"safe", "safe"}, {"admin", "dangerous"}, {"revoked", "safe"},
	} {
		if err := st.MCPTokens().Create(ctx, tok.name, tok.name+"-token", tok.scope, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.MCPTokens().Revoke(ctx, "revoked", now); err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: st, agents: &fakeAgents{}, dir: filepath.Join(t.TempDir(), "automations")}
	f.pol = policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	f.kube = &fakeKube{pol: f.pol}
	mcfg := Config{
		Devices: st.Devices(), Tokens: st.MCPTokens(), Policy: f.pol, Agents: f.agents, Kube: f.kube,
		AutomationsDir: f.dir, Log: slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(&mcfg)
	}
	srv := httptest.NewServer(Handler(mcfg))
	t.Cleanup(srv.Close)
	f.url = srv.URL + Path
	return f
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// connect opens an MCP session with token.
func (f *fixture) connect(t *testing.T, token string) (*mcp.ClientSession, error) {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, err := c.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint: f.url, HTTPClient: &http.Client{Transport: bearer{token}}, MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err == nil {
		t.Cleanup(func() { _ = cs.Close() })
	}
	return cs, err
}

func (f *fixture) mustConnect(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()
	cs, err := f.connect(t, token)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// call calls a tool and returns its text and whether it is a tool error.
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return err.Error(), true
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

// lastAudit returns the newest audit entry.
func (f *fixture) lastAudit(t *testing.T) store.AuditEntry {
	t.Helper()
	e, err := f.st.Audit().List(t.Context(), 1)
	if err != nil || len(e) != 1 {
		t.Fatalf("audit = %v, %v", e, err)
	}
	return e[0]
}

func TestAuth(t *testing.T) {
	f := newFixture(t, policy.Config{})
	for name, header := range map[string]string{ //nolint:gosec // test tokens
		"no token":      "",
		"not bearer":    "Basic c2FmZS10b2tlbg==",
		"unknown token": "Bearer nope",
		"revoked token": "Bearer revoked-token",
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, f.url,
				strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized || res.Header.Get("WWW-Authenticate") == "" {
				t.Fatalf("status %d, body %s", res.StatusCode, body)
			}
		})
	}
	if _, err := f.connect(t, "revoked-token"); err == nil {
		t.Error("a client connected with a revoked token")
	}
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, tl := range res.Tools {
		out = append(out, tl.Name)
	}
	slices.Sort(out)
	return out
}

func TestToolsFollowTheScope(t *testing.T) {
	f := newFixture(t, policy.Config{})
	reads := []string{"device_metrics", "get_device", "list_devices", "list_kube_objects", "plan_automation", "pod_logs"}
	safe := append(slices.Clone(reads), "kube_action", "restart_service")
	all := append(slices.Clone(safe), "apply_automation", "exec_command")
	for _, s := range [][]string{reads, safe, all} {
		slices.Sort(s)
	}
	for token, want := range map[string][]string{"reader-token": reads, "safe-token": safe, "admin-token": all} {
		if got := toolNames(t, f.mustConnect(t, token)); !slices.Equal(got, want) {
			t.Errorf("%s: tools %v, want %v", token, got, want)
		}
	}
}

func TestReadTools(t *testing.T) {
	f := newFixture(t, policy.Config{})
	cs := f.mustConnect(t, "reader-token")
	tests := []struct {
		tool   string
		args   map[string]any
		want   string
		action policy.Action
	}{
		{"list_devices", nil, `"name": "pi"`, policy.DeviceRead},
		{"list_devices", map[string]any{"query": "room=attic"}, `"id": "dev-1"`, policy.DeviceRead},
		{"list_devices", map[string]any{"query": "nas"}, `[]`, policy.DeviceRead},
		{"get_device", map[string]any{"device": "pi.lan"}, `"cpus": 4`, policy.DeviceRead},
		{"list_kube_objects", nil, `"name": "lab"`, policy.KubeRead},
		{"list_kube_objects", map[string]any{"cluster": "lab", "kind": "pods", "namespace": "default"}, `"web-1"`, policy.KubeRead},
		{"pod_logs", map[string]any{"cluster": "lab", "namespace": "default", "pod": "web-1"}, "line 1", policy.KubePodLogs},
		{
			"plan_automation",
			map[string]any{"yaml": "id: hello\ntriggers:\n  - type: manual\nactions:\n  - type: log\n    message: hi\n"},
			"Automation hello", policy.AutomationPlan,
		},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			text, isErr := call(t, cs, tt.tool, tt.args)
			if isErr || !strings.Contains(text, tt.want) {
				t.Fatalf("%s = %q (error %v), want %q", tt.tool, text, isErr, tt.want)
			}
			e := f.lastAudit(t)
			if e.ActorKind != policy.ActorMCP || e.ActorID != "reader" || e.Action != string(tt.action) || e.Decision != policy.Allow {
				t.Errorf("audit = %+v", e)
			}
		})
	}
	if text, isErr := call(t, cs, "get_device", map[string]any{"device": "nas"}); !isErr {
		t.Errorf("get_device(nas) = %q, want an error", text)
	}
	if text, isErr := call(t, cs, "device_metrics", map[string]any{"device": "pi"}); !isErr || !strings.Contains(text, "no metrics source") {
		t.Errorf("device_metrics without a metrics source = %q", text)
	}
	// A read token is not offered actions, and cannot call them.
	if _, isErr := call(t, cs, "restart_service", map[string]any{"device": "pi", "service": "docker:web"}); !isErr {
		t.Error("a read token restarted a service")
	}
	if f.agents.count() != 0 {
		t.Error("a request reached an agent")
	}
}

func TestRestartService(t *testing.T) {
	f := newFixture(t, policy.Config{})
	cs := f.mustConnect(t, "safe-token")
	text, isErr := call(t, cs, "restart_service", map[string]any{"device": "pi", "service": "docker:web"})
	if isErr {
		t.Fatalf("restart_service = %q", text)
	}
	if f.agents.count() != 1 || f.agents.sent[0].GetRestart().GetManager() != "docker" || f.agents.sent[0].GetRestart().GetName() != "web" {
		t.Fatalf("sent %v", f.agents.sent)
	}
	e := f.lastAudit(t)
	if e.ActorKind != policy.ActorMCP || e.ActorID != "safe" || e.Action != string(policy.DeviceRestart) ||
		e.Decision != policy.Allow || e.Result != "ok" || e.Target != "pi" {
		t.Errorf("audit = %+v", e)
	}

	// A dry run only decides.
	if text, isErr := call(t, cs, "restart_service", map[string]any{"device": "pi", "service": "docker:web", "dry_run": true}); isErr || !strings.Contains(text, "would be allowed") {
		t.Errorf("dry run = %q", text)
	}
	if f.agents.count() != 1 || f.lastAudit(t).Result != policy.DryRun {
		t.Errorf("dry run sent %d requests; audit %+v", f.agents.count(), f.lastAudit(t))
	}
	if _, isErr := call(t, cs, "restart_service", map[string]any{"device": "pi", "service": "web"}); !isErr {
		t.Error("restart of a service without a manager succeeded")
	}
}

// Negative cases: nothing reaches a device, and the denial is audited as
// the token.
func TestActionsDenied(t *testing.T) {
	restart := map[string]any{"device": "pi", "service": "docker:web"}
	tests := []struct {
		name    string
		cfg     policy.Config
		token   string
		tool    string
		args    map[string]any
		ceiling error
		reason  string
	}{
		{"denied by the policy file", policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
			policy.ActorMCP: {policy.Safe: policy.ModeDeny},
		}}, "safe-token", "restart_service", restart, nil, "denied by the policy configuration"},
		{"beyond the device ceiling", policy.Config{}, "safe-token", "restart_service", restart, policy.ErrBeyondCeiling, "ceiling"},
		{
			"a safe token cannot drain",
			policy.Config{},
			"safe-token", "kube_action",
			map[string]any{"cluster": "lab", "action": "drain", "name": "pi-1"},
			nil, "scope",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.cfg)
			f.agents.check = tt.ceiling
			cs := f.mustConnect(t, tt.token)
			text, isErr := call(t, cs, tt.tool, tt.args)
			if !isErr || !strings.Contains(text, "denied") {
				t.Fatalf("%s = %q, want denied", tt.tool, text)
			}
			if f.agents.count() != 0 || len(f.kube.ran) != 0 {
				t.Fatal("a denied action ran")
			}
			e := f.lastAudit(t)
			if e.ActorKind != policy.ActorMCP || e.ActorID != "safe" || e.Decision != policy.Deny || !strings.Contains(e.Result, tt.reason) {
				t.Errorf("audit = %+v, want a denial for %q", e, tt.reason)
			}
		})
	}
}

// A dangerous action of a dangerous token is held until an operator
// approves it; then it runs.
func TestDangerousActionNeedsApproval(t *testing.T) {
	f := newFixture(t, policy.Config{})
	cs := f.mustConnect(t, "admin-token")

	approved := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for ctx.Err() == nil {
			aps, err := f.st.Approvals().List(ctx, store.ApprovalPending, 1)
			if err == nil && len(aps) == 1 {
				if aps[0].ActorKind != policy.ActorMCP || aps[0].ActorID != "admin" || aps[0].Action != string(policy.DeviceExec) ||
					!strings.Contains(string(aps[0].Detail), "uptime") {
					approved <- errors.New("unexpected approval " + aps[0].ActorID + " " + aps[0].Action + " " + string(aps[0].Detail))
					return
				}
				if f.agents.count() != 0 {
					approved <- errors.New("the command ran before it was approved")
					return
				}
				approved <- f.pol.Decide(ctx, policy.ActorAdmin, "root", aps[0].ID, true)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		approved <- ctx.Err()
	}()
	text, isErr := call(t, cs, "exec_command", map[string]any{"device": "pi", "command": []string{"/usr/bin/uptime"}})
	if err := <-approved; err != nil {
		t.Fatal(err)
	}
	if isErr || f.agents.count() != 1 {
		t.Fatalf("exec_command = %q (error %v), sent %d", text, isErr, f.agents.count())
	}
	e := f.lastAudit(t)
	if e.Action != string(policy.DeviceExec) || e.Decision != policy.Allow || !strings.Contains(string(e.Detail), "admin/root") {
		t.Errorf("audit = %+v", e)
	}
}

func TestApplyAutomation(t *testing.T) {
	f := newFixture(t, policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorMCP: {policy.Dangerous: policy.ModeAllow},
	}})
	cs := f.mustConnect(t, "admin-token")
	yaml := "id: hello\ntriggers:\n  - type: manual\nactions:\n  - type: log\n    message: hi\n"
	path := filepath.Join(f.dir, "hello.yaml")

	if text, isErr := call(t, cs, "apply_automation", map[string]any{"yaml": yaml, "dry_run": true}); isErr || !strings.Contains(text, "Dry run") {
		t.Fatalf("dry run = %q", text)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a dry run wrote the file")
	}
	if text, isErr := call(t, cs, "apply_automation", map[string]any{"yaml": yaml}); isErr {
		t.Fatalf("apply = %q", text)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != yaml {
		t.Fatalf("file = %q, %v", b, err)
	}
	e := f.lastAudit(t)
	if e.Action != string(policy.AutomationApply) || e.Target != "hello" || e.Decision != policy.Allow || !strings.Contains(string(e.Detail), "hello.yaml") {
		t.Errorf("audit = %+v", e)
	}
	// The plan quotes commands and messages: it is for an approver only.
	if strings.Contains(string(e.Detail), "Automation hello") {
		t.Errorf("the audit entry holds the plan: %s", e.Detail)
	}
	// Another file with the same id would break the hub's reload.
	if err := os.Rename(path, filepath.Join(f.dir, "other.yaml")); err != nil {
		t.Fatal(err)
	}
	if text, isErr := call(t, cs, "apply_automation", map[string]any{"yaml": yaml}); !isErr || !strings.Contains(text, "other.yaml") {
		t.Errorf("apply over another file's id = %q", text)
	}
	if _, isErr := call(t, cs, "apply_automation", map[string]any{"yaml": "id: Bad\n"}); !isErr {
		t.Error("an invalid automation was applied")
	}
}
