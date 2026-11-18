// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

// automationDo runs RunAction as the automation runtime does: inside the
// policy decision on the automation's request, with its own engine.
func automationDo(t *testing.T, f *fixture, pol *policy.Engine, automationID string, req ActionRequest) (ActionResult, error) {
	t.Helper()
	pa, err := RequestPolicy(req)
	if err != nil {
		t.Fatal(err)
	}
	var res ActionResult
	err = pol.Do(t.Context(), policy.Request{
		ActorKind: policy.ActorAutomation, ActorID: automationID, Action: pa, Target: "lab/" + req.Name,
	}, func(ctx context.Context) error {
		var err error
		res, err = f.m.RunAction(ctx, "lab", req)
		return err
	})
	return res, err
}

// RunAction refuses to run outside a policy decision that allowed its very
// action, before anything reaches the cluster.
func TestRunActionNeedsAGrant(t *testing.T) {
	f, _ := actionCluster(t)
	for _, req := range everyAction {
		if _, err := f.m.RunAction(t.Context(), "lab", req); !errors.Is(err, ErrNotGranted) {
			t.Errorf("%s outside policy = %v, want ErrNotGranted", req.Action, err)
		}
	}
	// Granted another action is not granted this one.
	err := policy.New(f.st.Audit()).Do(t.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: webActor, Action: policy.KubeNodeCordon, Target: "lab/pi-1",
	}, func(ctx context.Context) error {
		_, err := f.m.RunAction(ctx, "lab", ActionRequest{Action: ActionDrain, Name: "pi-1"})
		return err
	})
	if !errors.Is(err, ErrNotGranted) {
		t.Errorf("drain under a cordon's grant = %v, want ErrNotGranted", err)
	}
	if got := f.api.actionRequests(); len(got) != 0 {
		t.Errorf("ungranted actions sent %v", got)
	}
}

// An automation may restart a workload; it may drain a node only when
// granted dangerous actions. A denied drain sends nothing to the cluster.
func TestAutomationActions(t *testing.T) {
	f, _ := actionCluster(t)
	pol := policy.NewWithConfig(f.st.Audit(), nil, policy.Config{DangerousAutomations: []string{"drainer"}})

	res, err := automationDo(t, f, pol, "restarter", everyAction[0])
	if err != nil || !strings.HasPrefix(res.Result, "Restart of Deployment default/web started") {
		t.Fatalf("restart = %+v, %v", res, err)
	}
	dep := f.api.object("/apis/apps/v1/deployments", "default/web")
	ann, _ := dep["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["annotations"].(map[string]any)
	if _, ok := ann[restartedAtAnnotation]; !ok {
		t.Errorf("restart: template annotations = %v", ann)
	}
	sent := len(f.api.actionRequests())

	drain := ActionRequest{Action: ActionDrain, Name: "pi-1"}
	if _, err := automationDo(t, f, pol, "nightly", drain); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("ungranted drain = %v, want ErrDenied", err)
	}
	if got := f.api.actionRequests()[sent:]; len(got) != 0 {
		t.Errorf("a denied drain sent %v", got)
	}
	if spec, _ := f.api.object("/api/v1/nodes", "/pi-1")["spec"].(map[string]any); spec["unschedulable"] == true {
		t.Error("a denied drain cordoned the node")
	}

	if res, err := automationDo(t, f, pol, "drainer", drain); err != nil || !strings.HasPrefix(res.Result, "Drained node pi-1") {
		t.Fatalf("granted drain = %+v, %v", res, err)
	}

	// One audit entry per decision, all with the automation as the actor.
	for action, want := range map[policy.Action][]string{
		policy.KubeWorkloadRestart: {"restarter:allow"},
		policy.KubeNodeDrain:       {"drainer:allow", "nightly:deny"},
	} {
		es := auditOf(t, f.st, action)
		var got []string
		for _, e := range es {
			if e.ActorKind != policy.ActorAutomation {
				t.Errorf("audit %+v: actor kind %s", e, e.ActorKind)
			}
			got = append(got, e.ActorID+":"+e.Decision)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("audit of %s = %v, want %v", action, got, want)
		}
	}
}

// PlanAction only reads, and decides and audits nothing.
func TestPlanAction(t *testing.T) {
	f, _ := actionCluster(t)
	res, err := f.m.PlanAction(t.Context(), "lab", ActionRequest{Action: ActionDrain, Name: "pi-1"})
	if err != nil || !res.DryRun || res.Class != string(policy.Dangerous) || !strings.HasPrefix(res.Summary, "Drain node pi-1") {
		t.Fatalf("plan = %+v, %v", res, err)
	}
	for _, r := range f.api.actionRequests() {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("a plan sent %s", r)
		}
	}
	if es := auditOf(t, f.st, policy.KubeNodeDrain); len(es) != 0 {
		t.Errorf("a plan was audited: %+v", es)
	}
	if _, err := f.m.PlanAction(t.Context(), "nope", everyAction[0]); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown cluster = %v, want ErrNotFound", err)
	}
	if _, err := RequestPolicy(ActionRequest{Action: ActionScale, Kind: "Deployment", Namespace: "default", Name: "web"}); !errors.Is(err, ErrBadAction) {
		t.Errorf("scale without replicas = %v, want ErrBadAction", err)
	}
}
