// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/policy"
)

// Actions of Act.
const (
	ActionRestart   = "restart"
	ActionScale     = "scale"
	ActionDeletePod = "delete_pod"
	ActionCordon    = "cordon"
	ActionUncordon  = "uncordon"
	ActionDrain     = "drain"
)

const (
	// DefaultDrainTimeout bounds a drain that sets no timeout.
	DefaultDrainTimeout = 2 * time.Minute
	// MaxDrainTimeout is the longest timeout a drain may set.
	MaxDrainTimeout = 10 * time.Minute
	// actionTimeout bounds every other action, and planning a drain.
	actionTimeout = 30 * time.Second
	// defaultEvictRetry is how long a drain waits before it retries an
	// eviction a PodDisruptionBudget refused, as kubectl drain does.
	defaultEvictRetry = 5 * time.Second
	// defaultGonePoll is how often a drain checks that an evicted pod is gone.
	defaultGonePoll = time.Second

	restartedAtAnnotation = "kubectl.kubernetes.io/restartedAt"
	mirrorAnnotation      = "kubernetes.io/config.mirror"
)

// Errors of Act.
var (
	ErrBadAction      = errors.New("invalid action")
	ErrObjectNotFound = errors.New("no such object in the cluster")
	// ErrDrainIncomplete marks a drain that stopped after it cordoned the node:
	// some of its work is done and some is not.
	ErrDrainIncomplete = errors.New("the drain is incomplete")
	// ErrWriteOutcomeUnknown marks a write that was sent and never answered:
	// the cluster may have carried it out.
	ErrWriteOutcomeUnknown = errors.New("the request may have reached the cluster")
)

// ActionRequest is a Kubernetes action on one object of a cluster.
type ActionRequest struct {
	Action string `json:"action"`
	// Kind is the workload's kind for a restart (Deployment, StatefulSet or
	// DaemonSet) or a scale (Deployment or StatefulSet).
	Kind string `json:"kind,omitempty"`
	// Namespace of the workload or pod; empty for a node.
	Namespace string `json:"namespace,omitempty"`
	// Name of the workload, pod or node.
	Name string `json:"name"`
	// Replicas is the scale's target.
	Replicas *int32 `json:"replicas,omitempty"`
	// TimeoutSeconds bounds a drain: DefaultDrainTimeout if 0.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// DryRun only plans the action: it reads the objects involved and
	// changes nothing.
	DryRun bool `json:"dry_run,omitempty"`
}

// ActionResult is the plan of an action and, unless it was a dry run, what
// came of it.
type ActionResult struct {
	Action string `json:"action"`
	// Class is the action's policy class: safe or dangerous.
	Class string `json:"class"`
	// Target is the object, within the cluster.
	Target   string   `json:"target"`
	DryRun   bool     `json:"dry_run"`
	Summary  string   `json:"summary"`
	Steps    []string `json:"steps"`
	Warnings []string `json:"warnings"`
	// Result is what the action did; empty for a dry run.
	Result string `json:"result,omitempty"`
}

// plan is what an action will do, read from the cluster.
type plan struct {
	summary  string
	steps    []string
	warnings []string
	// apply carries the plan out and says what it did; nil when there is
	// nothing to do.
	apply func(ctx context.Context) (string, error)
}

// kubeAction is a validated request.
type kubeAction struct {
	policy  policy.Action
	target  string
	detail  map[string]any
	timeout time.Duration
	plan    func(ctx context.Context) (*plan, error)
}

// ErrNotGranted is returned by RunAction outside a policy decision that
// allowed the action.
var ErrNotGranted = errors.New("not allowed by policy")

// Act plans req on cluster id and, unless it is a dry run, carries it out on
// behalf of actorKind/actorID (a web session, or an MCP client). Carrying it
// out is a policy action, decided before anything is sent to the cluster and
// audited; a dry run only reads the objects involved, as the snapshot does,
// and is decided and audited as a dry run.
func (m *Manager) Act(ctx context.Context, actorKind, actorID, id string, req ActionRequest) (ActionResult, error) {
	r, info, err := m.get(id)
	if err != nil {
		return ActionResult{}, err
	}
	p, err := m.prepare(r, info, req)
	if err != nil {
		return ActionResult{}, err
	}
	detail := map[string]any{"cluster_id": id}
	maps.Copy(detail, p.a.detail)
	polReq := policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: p.a.policy,
		Target: info.Name + "/" + p.a.target, Detail: detail, DryRun: req.DryRun,
	}
	if req.DryRun {
		if err := p.plan(ctx); err != nil {
			return ActionResult{}, actionError(req, err)
		}
		// The engine decides and audits a dry run, and never runs it.
		if err := m.policy.Do(ctx, polReq, func(context.Context) error { return nil }); err != nil {
			return ActionResult{}, actionError(req, err)
		}
		return p.res, nil
	}
	if err := m.policy.Do(ctx, polReq, p.apply); err != nil {
		return ActionResult{}, actionError(req, err)
	}
	return p.res, nil
}

// PlanAction plans req on the cluster named cluster, as a dry run of Act
// does, without deciding or auditing it: it only reads the objects
// involved, as the snapshot does. It is for callers that decide on req
// themselves, such as automations.
func (m *Manager) PlanAction(ctx context.Context, cluster string, req ActionRequest) (ActionResult, error) {
	p, err := m.prepareNamed(cluster, req)
	if err != nil {
		return ActionResult{}, err
	}
	p.res.DryRun = true
	if err := p.plan(ctx); err != nil {
		return ActionResult{}, actionError(req, err)
	}
	return p.res, nil
}

// RunAction carries out req on the cluster named cluster without auditing
// it, for a caller that wraps it in policy.Engine.Do itself, as the
// automation runtime does with its own actor. It runs only in a context
// policy granted req's action (policy.Granted), and fails with
// ErrNotGranted otherwise, before anything is sent to the cluster.
func (m *Manager) RunAction(ctx context.Context, cluster string, req ActionRequest) (ActionResult, error) {
	if req.DryRun {
		return ActionResult{}, badAction("a dry run is PlanAction")
	}
	p, err := m.prepareNamed(cluster, req)
	if err != nil {
		return ActionResult{}, err
	}
	if err := p.apply(ctx); err != nil {
		return ActionResult{}, actionError(req, err)
	}
	return p.res, nil
}

// RequestPolicy validates req as far as it can without a cluster, and
// returns the policy action that carrying it out is.
func RequestPolicy(req ActionRequest) (policy.Action, error) {
	a, err := (&Manager{}).action(nil, req)
	if err != nil {
		return "", err
	}
	return a.policy, nil
}

// prepared is a validated request on a running cluster, and its result.
type prepared struct {
	a   *kubeAction
	res ActionResult
}

func (m *Manager) prepareNamed(cluster string, req ActionRequest) (*prepared, error) {
	r, info, err := m.getNamed(cluster)
	if err != nil {
		return nil, err
	}
	return m.prepare(r, info, req)
}

func (m *Manager) prepare(r *running, info ClusterInfo, req ActionRequest) (*prepared, error) {
	a, err := m.action(r, req)
	if err != nil {
		return nil, err
	}
	if r.w == nil {
		return nil, fmt.Errorf("cluster %s: %s", info.Name, r.err)
	}
	class, _ := policy.ClassOf(a.policy)
	return &prepared{a: a, res: ActionResult{
		Action: req.Action, Class: string(class), Target: a.target, DryRun: req.DryRun,
		Steps: []string{}, Warnings: []string{},
	}}, nil
}

func (p *prepared) fill(pl *plan) {
	p.res.Summary = pl.summary
	p.res.Steps = append(p.res.Steps, pl.steps...)
	p.res.Warnings = append(p.res.Warnings, pl.warnings...)
}

// plan reads the objects involved and fills the result's plan.
func (p *prepared) plan(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, actionTimeout)
	defer cancel()
	pl, err := p.a.plan(ctx)
	if err != nil {
		return err
	}
	p.fill(pl)
	return nil
}

// apply plans the action and carries it out, only in a context policy
// granted it.
func (p *prepared) apply(ctx context.Context) error {
	if !policy.Granted(ctx, p.a.policy) {
		return fmt.Errorf("%s: %w", p.a.policy, ErrNotGranted)
	}
	ctx, cancel := context.WithTimeout(ctx, p.a.timeout)
	defer cancel()
	pl, err := p.a.plan(ctx)
	if err != nil {
		return err
	}
	p.fill(pl)
	if pl.apply == nil {
		p.res.Result = "Nothing to do."
		return nil
	}
	p.res.Result, err = pl.apply(ctx)
	return err
}

func actionError(req ActionRequest, err error) error {
	if errors.Is(err, policy.ErrDenied) {
		return err
	}
	if hasCode(err, http.StatusNotFound) {
		err = fmt.Errorf("%w: %w", ErrObjectNotFound, err)
	}
	return fmt.Errorf("%s %s: %w", req.Action, req.Name, err)
}

// workloadResources are the workload kinds an action may name, by their API
// resource.
var workloadResources = map[string]string{
	"Deployment":  "deployments",
	"StatefulSet": "statefulsets",
	"DaemonSet":   "daemonsets",
}

func badAction(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadAction, fmt.Sprintf(format, args...))
}

// action validates req.
func (m *Manager) action(r *running, req ActionRequest) (*kubeAction, error) {
	if !validObjectName(req.Name) {
		return nil, badAction("name must be a Kubernetes object name")
	}
	switch req.Action {
	case ActionRestart, ActionScale, ActionDeletePod:
		if !validObjectName(req.Namespace) {
			return nil, badAction("namespace must be a Kubernetes namespace name")
		}
	}
	c := func() *apiClient { return r.w.c }
	switch req.Action {
	case ActionRestart, ActionScale:
		res, ok := workloadResources[req.Kind]
		switch {
		case !ok && req.Action == ActionRestart:
			return nil, badAction("restart: kind must be Deployment, StatefulSet or DaemonSet")
		case !ok || req.Kind == "DaemonSet":
			return nil, badAction("scale: kind must be Deployment or StatefulSet")
		}
		w := workloadRef{
			kind: req.Kind, path: "/apis/apps/v1/namespaces/" + req.Namespace + "/" + res + "/" + req.Name,
			name: req.Kind + " " + req.Namespace + "/" + req.Name,
		}
		a := &kubeAction{
			target: req.Kind + "/" + req.Namespace + "/" + req.Name, timeout: actionTimeout,
			detail: map[string]any{},
		}
		if req.Action == ActionRestart {
			a.policy = policy.KubeWorkloadRestart
			a.plan = func(ctx context.Context) (*plan, error) { return m.planRestart(ctx, c(), w) }
			return a, nil
		}
		if req.Replicas == nil || *req.Replicas < 0 {
			return nil, badAction("scale: replicas must be 0 or more")
		}
		n := *req.Replicas
		a.policy, a.detail["replicas"] = policy.KubeWorkloadScale, n
		a.plan = func(ctx context.Context) (*plan, error) { return planScale(ctx, c(), w, n) }
		return a, nil
	case ActionDeletePod:
		return &kubeAction{
			policy: policy.KubePodDelete, target: req.Namespace + "/" + req.Name, timeout: actionTimeout,
			plan: func(ctx context.Context) (*plan, error) { return planDeletePod(ctx, c(), req.Namespace, req.Name) },
		}, nil
	case ActionCordon, ActionUncordon:
		pa, cordon := policy.KubeNodeCordon, req.Action == ActionCordon
		if !cordon {
			pa = policy.KubeNodeUncordon
		}
		return &kubeAction{
			policy: pa, target: req.Name, timeout: actionTimeout,
			plan: func(ctx context.Context) (*plan, error) { return planCordon(ctx, c(), req.Name, cordon) },
		}, nil
	case ActionDrain:
		timeout := DefaultDrainTimeout
		if req.TimeoutSeconds != 0 {
			timeout = time.Duration(req.TimeoutSeconds) * time.Second
			if req.TimeoutSeconds < 0 || timeout > MaxDrainTimeout {
				return nil, badAction("drain: timeout_seconds must be between 1 and %d", int(MaxDrainTimeout.Seconds()))
			}
		}
		return &kubeAction{
			policy: policy.KubeNodeDrain, target: req.Name, timeout: timeout + actionTimeout,
			detail: map[string]any{"timeout": timeout.String()},
			plan:   func(ctx context.Context) (*plan, error) { return m.planDrain(ctx, c(), req.Name, timeout) },
		}, nil
	}
	return nil, badAction("unknown action %q", req.Action)
}

// workloadRef is a workload an action names.
type workloadRef struct {
	kind, path string
	// name is "Kind namespace/name", for messages.
	name string
}

// workloadSpec is the part of a Deployment, StatefulSet or DaemonSet the
// actions read.
type workloadSpec struct {
	Spec struct {
		Replicas *int32 `json:"replicas"`
		// Strategy is a Deployment's, UpdateStrategy a StatefulSet's or
		// DaemonSet's.
		Strategy struct {
			Type string `json:"type"`
		} `json:"strategy"`
		UpdateStrategy struct {
			Type string `json:"type"`
		} `json:"updateStrategy"`
	} `json:"spec"`
	Status struct {
		DesiredNumberScheduled int32 `json:"desiredNumberScheduled"`
	} `json:"status"`
}

func (w *workloadSpec) replicas() int32 {
	if w.Spec.Replicas == nil {
		return 1
	}
	return *w.Spec.Replicas
}

func plural(n int, one string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}

func (m *Manager) planRestart(ctx context.Context, c *apiClient, w workloadRef) (*plan, error) {
	var spec workloadSpec
	if err := c.getObject(ctx, w.path, &spec); err != nil {
		return nil, err
	}
	pods := spec.replicas()
	if w.kind == "DaemonSet" {
		pods = spec.Status.DesiredNumberScheduled
	}
	p := &plan{
		summary: fmt.Sprintf("Restart %s: replace its %s with a rolling update, as kubectl rollout restart does.",
			w.name, plural(int(pods), "pod")),
		steps: []string{"Set the pod template annotation " + restartedAtAnnotation + " to the current time"},
	}
	switch {
	case pods == 0:
		p.warnings = append(p.warnings, "It has no pods: nothing restarts until it is scaled up.")
	case spec.Spec.Strategy.Type == "Recreate":
		p.warnings = append(p.warnings, "Its strategy is Recreate: every pod stops before the new ones start.")
	case spec.Spec.UpdateStrategy.Type == "OnDelete":
		p.warnings = append(p.warnings, "Its update strategy is OnDelete: a pod is only replaced when it is deleted.")
	}
	p.apply = func(ctx context.Context) (string, error) {
		patch := map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
			"annotations": map[string]string{restartedAtAnnotation: m.now().UTC().Format(time.RFC3339)},
		}}}}
		if err := c.send(ctx, http.MethodPatch, w.path, strategicPatch, patch); err != nil {
			return "", err
		}
		return fmt.Sprintf("Restart of %s started.", w.name), nil
	}
	return p, nil
}

func planScale(ctx context.Context, c *apiClient, w workloadRef, n int32) (*plan, error) {
	var spec workloadSpec
	if err := c.getObject(ctx, w.path, &spec); err != nil {
		return nil, err
	}
	cur := spec.replicas()
	if cur == n {
		return &plan{summary: fmt.Sprintf("%s already has %s: nothing changes.", w.name, plural(int(n), "replica"))}, nil
	}
	p := &plan{
		summary: fmt.Sprintf("Scale %s from %d to %s.", w.name, cur, plural(int(n), "replica")),
		steps:   []string{fmt.Sprintf("Set spec.replicas to %d through the scale subresource", n)},
	}
	if n == 0 {
		p.warnings = append(p.warnings, "Every pod of it stops.")
	}
	p.apply = func(ctx context.Context) (string, error) {
		patch := map[string]any{"spec": map[string]any{"replicas": n}}
		if err := c.send(ctx, http.MethodPatch, w.path+"/scale", mergePatch, patch); err != nil {
			return "", err
		}
		return fmt.Sprintf("Scaled %s to %s.", w.name, plural(int(n), "replica")), nil
	}
	return p, nil
}

func podPath(namespace, name string) string {
	return "/api/v1/namespaces/" + namespace + "/pods/" + name
}

func planDeletePod(ctx context.Context, c *apiClient, namespace, name string) (*plan, error) {
	var p pod
	path := podPath(namespace, name)
	if err := c.getObject(ctx, path, &p); err != nil {
		return nil, err
	}
	v := podOf(&p)
	where := "unscheduled"
	if v.Node != "" {
		where = "on node " + v.Node
	}
	out := &plan{
		summary: fmt.Sprintf("Delete pod %s/%s (%s, %s).", namespace, name, v.Status, where),
		steps:   []string{"Delete the pod, with its grace period"},
	}
	if v.Owner != "" {
		out.steps = append(out.steps, "Its controller "+v.Owner+" creates a replacement")
	} else {
		out.warnings = append(out.warnings, "It has no controller: nothing recreates it.")
	}
	out.apply = func(ctx context.Context) (string, error) {
		if err := c.deleteObject(ctx, path); err != nil {
			return "", err
		}
		return fmt.Sprintf("Deleted pod %s/%s.", namespace, name), nil
	}
	return out, nil
}

func nodePath(name string) string { return "/api/v1/nodes/" + name }

// setUnschedulable cordons or uncordons a node.
func setUnschedulable(ctx context.Context, c *apiClient, name string, v bool) error {
	return c.send(ctx, http.MethodPatch, nodePath(name), mergePatch, map[string]any{"spec": map[string]any{"unschedulable": v}})
}

func planCordon(ctx context.Context, c *apiClient, name string, cordon bool) (*plan, error) {
	var n node
	if err := c.getObject(ctx, nodePath(name), &n); err != nil {
		return nil, err
	}
	switch {
	case cordon && n.Spec.Unschedulable:
		return &plan{summary: fmt.Sprintf("Node %s is already cordoned: nothing changes.", name)}, nil
	case !cordon && !n.Spec.Unschedulable:
		return &plan{summary: fmt.Sprintf("Node %s is not cordoned: nothing changes.", name)}, nil
	}
	p := &plan{
		summary: fmt.Sprintf("Cordon node %s: no new pod is scheduled on it. The pods running there keep running.", name),
		steps:   []string{"Set spec.unschedulable to true"},
	}
	done := fmt.Sprintf("Cordoned node %s.", name)
	if !cordon {
		p.summary = fmt.Sprintf("Uncordon node %s: pods can be scheduled on it again.", name)
		p.steps = []string{"Set spec.unschedulable to false"}
		done = fmt.Sprintf("Uncordoned node %s.", name)
	}
	p.apply = func(ctx context.Context) (string, error) {
		return done, setUnschedulable(ctx, c, name, cordon)
	}
	return p, nil
}

// podExtra is the part of a pod only a drain reads.
type podExtra struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Volumes []volume `json:"volumes"`
	} `json:"spec"`
}

type volume struct {
	EmptyDir *struct{} `json:"emptyDir"`
}

// controllerKind is the kind of a pod's controller, "" if it has none.
func controllerKind(p *pod) string {
	for _, o := range p.Metadata.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return o.Kind
		}
	}
	return ""
}

func (m *Manager) planDrain(ctx context.Context, c *apiClient, name string, timeout time.Duration) (*plan, error) {
	var n node
	if err := c.getObject(ctx, nodePath(name), &n); err != nil {
		return nil, err
	}
	items, _, err := c.listSelected(ctx, "/api/v1/pods", "spec.nodeName="+name)
	if err != nil {
		return nil, err
	}
	var evict []pod
	var daemons, mirrors, unmanaged, emptyDir []string
	for _, raw := range items {
		var p pod
		var x podExtra
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("decode pod: %w", err)
		}
		if err := json.Unmarshal(raw, &x); err != nil {
			return nil, fmt.Errorf("decode pod: %w", err)
		}
		key := nsName(&p.Metadata)
		switch kind := controllerKind(&p); {
		case x.Metadata.Annotations[mirrorAnnotation] != "":
			mirrors = append(mirrors, key)
		case kind == "DaemonSet":
			daemons = append(daemons, key)
		default:
			evict = append(evict, p)
			if kind == "" {
				unmanaged = append(unmanaged, key)
			}
			if slices.ContainsFunc(x.Spec.Volumes, func(v volume) bool { return v.EmptyDir != nil }) {
				emptyDir = append(emptyDir, key)
			}
		}
	}
	slices.SortFunc(evict, func(a, b pod) int { return strings.Compare(nsName(&a.Metadata), nsName(&b.Metadata)) })

	p := &plan{summary: fmt.Sprintf("Drain node %s: cordon it, then evict its %s through the Eviction API, which "+
		"honours PodDisruptionBudgets. Waits up to %s for them to go.", name, plural(len(evict), "pod"), timeout)}
	if n.Spec.Unschedulable {
		p.steps = append(p.steps, "The node is already cordoned")
	} else {
		p.steps = append(p.steps, "Cordon the node")
	}
	for _, e := range evict {
		p.steps = append(p.steps, "Evict "+nsName(&e.Metadata))
	}
	if len(daemons) > 0 {
		p.steps = append(p.steps, "Skip DaemonSet pods: "+strings.Join(daemons, ", "))
	}
	if len(mirrors) > 0 {
		p.steps = append(p.steps, "Skip static (mirror) pods: "+strings.Join(mirrors, ", "))
	}
	if len(evict) > 0 {
		p.steps = append(p.steps, fmt.Sprintf("Retry an eviction a PodDisruptionBudget refuses every %s, until %s have passed", m.evictRetry, timeout))
	}
	if len(unmanaged) > 0 {
		p.warnings = append(p.warnings, "No controller recreates these pods: "+strings.Join(unmanaged, ", "))
	}
	if len(emptyDir) > 0 {
		p.warnings = append(p.warnings, "These pods lose their emptyDir data: "+strings.Join(emptyDir, ", "))
	}
	cordoned := n.Spec.Unschedulable
	p.apply = func(ctx context.Context) (string, error) {
		return m.drain(ctx, c, name, cordoned, evict, timeout)
	}
	return p, nil
}

// drain cordons node name unless it is, and evicts pods, all at once, each
// retrying while a PodDisruptionBudget refuses it, until they are gone or
// timeout. The node stays cordoned either way, as with kubectl drain.
func (m *Manager) drain(ctx context.Context, c *apiClient, name string, cordoned bool, pods []pod, timeout time.Duration) (string, error) {
	if !cordoned {
		if err := setUnschedulable(ctx, c, name, true); err != nil {
			return "", fmt.Errorf("cordon: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var (
		mu      sync.Mutex
		pending = map[string]string{} // pod -> why it is still there
	)
	for _, p := range pods {
		pending[nsName(&p.Metadata)] = "not evicted yet"
	}
	note := func(key, why string) {
		mu.Lock()
		defer mu.Unlock()
		if why == "" {
			delete(pending, key)
		} else {
			pending[key] = why
		}
	}
	g, gctx := errgroup.WithContext(ctx)
	for _, p := range pods {
		g.Go(func() error { return m.evict(gctx, c, p, note) })
	}
	err := g.Wait()
	mu.Lock()
	defer mu.Unlock()
	if err == nil {
		return fmt.Sprintf("Drained node %s: evicted %s.", name, plural(len(pods), "pod")), nil
	}
	left := make([]string, 0, len(pending))
	for _, k := range slices.Sorted(maps.Keys(pending)) {
		left = append(left, k+" ("+pending[k]+")")
	}
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
		err = fmt.Errorf("timed out after %s: %w", timeout, err)
	}
	return "", fmt.Errorf("node %s stays cordoned, %d of %d pods were not evicted: %s: %w: %w",
		name, len(pending), len(pods), strings.Join(left, ", "), ErrDrainIncomplete, err)
}

// evict evicts p and waits until it is gone, retrying every evictRetry while
// a PodDisruptionBudget refuses the eviction (HTTP 429).
func (m *Manager) evict(ctx context.Context, c *apiClient, p pod, note func(key, why string)) error {
	key := nsName(&p.Metadata)
	path := podPath(p.Metadata.Namespace, p.Metadata.Name)
	body := map[string]any{
		"apiVersion": "policy/v1", "kind": "Eviction",
		"metadata": map[string]string{"namespace": p.Metadata.Namespace, "name": p.Metadata.Name},
	}
	for {
		err := c.send(ctx, http.MethodPost, path+"/eviction", "", body)
		switch {
		case err == nil:
			note(key, "evicted, still terminating")
			if err := m.waitGone(ctx, c, path, p.Metadata.UID); err != nil {
				return err
			}
			note(key, "")
			return nil
		case hasCode(err, http.StatusNotFound):
			note(key, "")
			return nil
		case hasCode(err, http.StatusTooManyRequests):
			var ae *apiError
			errors.As(err, &ae)
			note(key, "refused: "+ae.Message)
			t := time.NewTimer(m.evictRetry)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		case ctx.Err() != nil:
			// Keep the last reason, such as a budget's refusal.
			return ctx.Err()
		default:
			note(key, err.Error())
			return fmt.Errorf("evict %s: %w", key, err)
		}
	}
}

// waitGone waits until the pod at path is deleted, or replaced by one with
// another UID (a StatefulSet's pod keeps its name).
func (m *Manager) waitGone(ctx context.Context, c *apiClient, path, uid string) error {
	t := time.NewTicker(m.gonePoll)
	defer t.Stop()
	for {
		var p struct {
			Metadata struct {
				UID string `json:"uid"`
			} `json:"metadata"`
		}
		err := c.getObject(ctx, path, &p)
		switch {
		case hasCode(err, http.StatusNotFound):
			return nil
		case err == nil && p.Metadata.UID != uid:
			return nil
		case err != nil && ctx.Err() != nil:
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
