// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

// nodeReadyDo runs NodeReady inside a policy decision on it, as a runbook's
// check does.
func nodeReadyDo(t *testing.T, f *fixture, pol *policy.Engine, cluster, node string) error {
	t.Helper()
	return pol.Do(t.Context(), policy.Request{
		ActorKind: policy.ActorAutomation, ActorID: "runbook/add-node", Action: policy.KubeNodeReady, Target: cluster + "/" + node,
	}, func(ctx context.Context) error { return f.m.NodeReady(ctx, cluster, node) })
}

func TestNodeReady(t *testing.T) {
	f, _ := actionCluster(t)
	f.api.put("/api/v1/nodes", nodeObj("pi-3", "192.168.2.133", false))
	denyReads := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: {policy.Read: policy.ModeDeny}}}
	for _, tt := range []struct {
		name, cluster, node string
		cfg                 policy.Config
		want                error
		reads               bool // whether the node was read
	}{
		{name: "ready", cluster: "lab", node: "pi-1", reads: true},
		{name: "not ready", cluster: "lab", node: "pi-3", want: ErrNodeNotReady, reads: true},
		{name: "missing node", cluster: "lab", node: "pi-9", want: ErrObjectNotFound, reads: true},
		{name: "unknown cluster", cluster: "nope", node: "pi-1", want: ErrNotFound},
		{name: "policy denies", cluster: "lab", node: "pi-1", cfg: denyReads, want: policy.ErrDenied},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := len(f.api.actionRequests())
			err := nodeReadyDo(t, f, policy.NewWithConfig(f.st.Audit(), nil, tt.cfg), tt.cluster, tt.node)
			if (tt.want == nil) != (err == nil) || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Fatalf("NodeReady = %v, want %v", err, tt.want)
			}
			sent := f.api.actionRequests()[before:]
			want := []string{}
			if tt.reads {
				want = []string{"GET /api/v1/nodes/" + tt.node}
			}
			if !slices.Equal(append([]string{}, sent...), want) {
				t.Errorf("requests = %v, want %v", sent, want)
			}
		})
	}
	// One audit entry per decision.
	if es := auditOf(t, f.st, policy.KubeNodeReady); len(es) != 5 {
		t.Errorf("audit entries = %d, want 5", len(es))
	}
}

func TestNodeReadyNeedsAGrant(t *testing.T) {
	f, _ := actionCluster(t)
	if err := f.m.NodeReady(t.Context(), "lab", "pi-1"); !errors.Is(err, ErrNotGranted) {
		t.Errorf("outside policy = %v, want ErrNotGranted", err)
	}
	if got := f.api.actionRequests(); len(got) != 0 {
		t.Errorf("sent %v", got)
	}
}

func TestDeleteNode(t *testing.T) {
	f, info := actionCluster(t)
	f.api.put("/api/v1/nodes", nodeObj("gone-1", "192.168.2.140", false))
	pol := policy.NewWithConfig(f.st.Audit(), nil, policy.Config{DangerousAutomations: []string{"runbook/add-node"}})
	del := func(automation, node string) (ActionResult, error) {
		return automationDo(t, f, pol, automation, ActionRequest{Action: ActionDeleteNode, Name: node})
	}

	// Denied: nothing is sent.
	if _, err := del("runbook/other", "gone-1"); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("ungranted delete = %v, want ErrDenied", err)
	}
	if got := f.api.actionRequests(); len(got) != 0 {
		t.Errorf("a denied delete sent %v", got)
	}

	// The plan reads and warns; it deletes nothing.
	res, err := f.m.PlanAction(t.Context(), "lab", ActionRequest{Action: ActionDeleteNode, Name: "pi-1"})
	if err != nil || res.Class != string(policy.Dangerous) || !strings.Contains(res.Summary, "Delete the Node object pi-1") ||
		len(res.Warnings) != 2 {
		t.Fatalf("plan = %+v, %v", res, err)
	}
	if f.api.object("/api/v1/nodes", "/pi-1") == nil {
		t.Fatal("a plan deleted the node")
	}

	// Granted: the node is deleted.
	res, err = del("runbook/add-node", "gone-1")
	if err != nil || res.Result != "Deleted node gone-1." {
		t.Fatalf("granted delete = %+v, %v", res, err)
	}
	if f.api.object("/api/v1/nodes", "/gone-1") != nil {
		t.Error("the node is still there")
	}
	if got := f.api.actionRequests(); !slices.Contains(got, "DELETE /api/v1/nodes/gone-1") {
		t.Errorf("requests = %v", got)
	}

	// A node that is not there leaves nothing to do, as a rollback needs.
	res, err = del("runbook/add-node", "never-joined")
	if err != nil || res.Result != "Nothing to do." {
		t.Fatalf("delete of a missing node = %+v, %v", res, err)
	}

	// One entry per decision: the log folds an outcome into its decision.
	var got []string
	for _, e := range auditOf(t, f.st, policy.KubeNodeDelete) {
		got = append(got, e.ActorID+":"+e.Decision+":"+e.Target)
	}
	want := []string{
		"runbook/other:deny:lab/gone-1",
		"runbook/add-node:allow:lab/gone-1", "runbook/add-node:allow:lab/never-joined",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("audit = %v, want %v", got, want)
	}

	// The web UI and MCP clients cannot delete a node.
	if _, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, info.ID, ActionRequest{Action: ActionDeleteNode, Name: "pi-2"}); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("web delete = %v, want ErrDenied", err)
	}
}
