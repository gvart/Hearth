// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
)

// Kube carries out Kubernetes actions on the clusters the hub adopted, by
// cluster name: *kubernetes.Manager. RunAction must not audit: the runtime
// runs it inside its own policy decision, and it refuses to run outside one.
type Kube interface {
	PlanAction(ctx context.Context, cluster string, req kubernetes.ActionRequest) (kubernetes.ActionResult, error)
	RunAction(ctx context.Context, cluster string, req kubernetes.ActionRequest) (kubernetes.ActionResult, error)
}

// kubeActions returns the kube_* action kinds.
func kubeActions(k Kube) map[string]Builder[Action] {
	return map[string]Builder[Action]{
		"kube_restart": func(p Params) (Action, error) {
			var cfg struct {
				Cluster   string `yaml:"cluster"`
				Kind      string `yaml:"kind"`
				Namespace string `yaml:"namespace"`
				Name      string `yaml:"name"`
			}
			if err := p.Decode(&cfg); err != nil {
				return nil, err
			}
			return buildKube(p, k, kubeFields{
				verb: kubernetes.ActionRestart, cluster: cfg.Cluster, kind: cfg.Kind, namespace: cfg.Namespace, name: cfg.Name,
			})
		},
		"kube_scale": func(p Params) (Action, error) {
			var cfg struct {
				Cluster   string `yaml:"cluster"`
				Kind      string `yaml:"kind"`
				Namespace string `yaml:"namespace"`
				Name      string `yaml:"name"`
				Replicas  *int32 `yaml:"replicas"`
			}
			if err := p.Decode(&cfg); err != nil {
				return nil, err
			}
			return buildKube(p, k, kubeFields{
				verb: kubernetes.ActionScale, cluster: cfg.Cluster, kind: cfg.Kind, namespace: cfg.Namespace, name: cfg.Name,
				replicas: cfg.Replicas,
			})
		},
		"kube_delete_pod": func(p Params) (Action, error) {
			var cfg struct {
				Cluster   string `yaml:"cluster"`
				Namespace string `yaml:"namespace"`
				Name      string `yaml:"name"`
			}
			if err := p.Decode(&cfg); err != nil {
				return nil, err
			}
			return buildKube(p, k, kubeFields{
				verb: kubernetes.ActionDeletePod, cluster: cfg.Cluster, namespace: cfg.Namespace, name: cfg.Name,
			})
		},
		"kube_cordon":   func(p Params) (Action, error) { return buildKubeNode(p, k, kubernetes.ActionCordon) },
		"kube_uncordon": func(p Params) (Action, error) { return buildKubeNode(p, k, kubernetes.ActionUncordon) },
		"kube_drain": func(p Params) (Action, error) {
			var cfg struct {
				Cluster string        `yaml:"cluster"`
				Node    string        `yaml:"node"`
				Timeout time.Duration `yaml:"timeout"`
			}
			if err := p.Decode(&cfg); err != nil {
				return nil, err
			}
			return buildKube(p, k, kubeFields{
				verb: kubernetes.ActionDrain, cluster: cfg.Cluster, name: cfg.Node, node: true, timeout: cfg.Timeout,
			})
		},
	}
}

func buildKubeNode(p Params, k Kube, verb string) (Action, error) {
	var cfg struct {
		Cluster string `yaml:"cluster"`
		Node    string `yaml:"node"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	return buildKube(p, k, kubeFields{verb: verb, cluster: cfg.Cluster, name: cfg.Node, node: true})
}

// kubeFields are the fields of a kube_* action as written.
type kubeFields struct {
	verb, cluster, kind, namespace, name string
	// node says name is the node field.
	node     bool
	replicas *int32
	timeout  time.Duration
}

// kubeAction is a Kubernetes action on an adopted cluster. Cluster,
// namespace, name and node may be templates.
type kubeAction struct {
	kube                     Kube
	cluster, namespace, name Text
	// req holds the fields that are not templates.
	req    kubernetes.ActionRequest
	policy policy.Action
	target Text
	desc   string
}

func buildKube(p Params, k Kube, f kubeFields) (Action, error) {
	nameField := "name"
	if f.node {
		nameField = "node"
	}
	required := map[string]string{"cluster": f.cluster, nameField: f.name}
	if !f.node {
		required["namespace"] = f.namespace
	}
	for _, field := range []string{"cluster", "namespace", nameField} {
		if v, ok := required[field]; ok && v == "" {
			return nil, fmt.Errorf("%s is required", field)
		}
	}
	a := &kubeAction{kube: k, req: kubernetes.ActionRequest{Action: f.verb, Kind: f.kind, Replicas: f.replicas}}
	var err error
	if a.cluster, err = p.Text(f.cluster, "cluster"); err != nil {
		return nil, err
	}
	if a.namespace, err = p.Text(f.namespace, "namespace"); err != nil {
		return nil, err
	}
	if a.name, err = p.Text(f.name, nameField); err != nil {
		return nil, err
	}
	if f.timeout < 0 {
		return nil, errors.New("timeout must not be negative")
	}
	a.req.TimeoutSeconds = int(math.Ceil(f.timeout.Seconds()))

	// Check what can be checked before a run: templated names stand in as
	// a valid one.
	check := a.req
	check.Namespace, check.Name = placeholder(a.namespace), placeholder(a.name)
	if a.policy, err = kubernetes.RequestPolicy(check); err != nil {
		return nil, errors.New(strings.TrimPrefix(err.Error(), kubernetes.ErrBadAction.Error()+": "))
	}

	// The target is the one the web UI's actions audit: cluster/object.
	object := f.namespace + "/" + f.name
	switch {
	case f.node:
		object = f.name
	case f.kind != "":
		object = f.kind + "/" + object
	}
	if a.target, err = p.Text(f.cluster+"/"+object, "cluster"); err != nil {
		return nil, err
	}

	in := " in cluster " + f.cluster
	switch f.verb {
	case kubernetes.ActionRestart:
		a.desc = fmt.Sprintf("rolling restart of %s %s/%s%s, as kubectl rollout restart", f.kind, f.namespace, f.name, in)
	case kubernetes.ActionScale:
		a.desc = fmt.Sprintf("scale %s %s/%s to %d replicas%s", f.kind, f.namespace, f.name, *f.replicas, in)
	case kubernetes.ActionDeletePod:
		a.desc = fmt.Sprintf("delete pod %s/%s%s; its controller, if any, recreates it", f.namespace, f.name, in)
	case kubernetes.ActionCordon:
		a.desc = fmt.Sprintf("cordon node %s%s", f.name, in)
	case kubernetes.ActionUncordon:
		a.desc = fmt.Sprintf("uncordon node %s%s", f.name, in)
	case kubernetes.ActionDrain:
		timeout := kubernetes.DefaultDrainTimeout
		if a.req.TimeoutSeconds > 0 {
			timeout = time.Duration(a.req.TimeoutSeconds) * time.Second
		}
		a.desc = fmt.Sprintf("drain node %s%s: cordon it and evict its pods, honouring PodDisruptionBudgets, waiting up to %s",
			f.name, in, timeout)
	}
	return a, nil
}

// placeholder is the value a field is checked with when the file is
// loaded: itself, or a valid object name if it is a template.
func placeholder(x Text) string {
	if x.t != nil {
		return "templated"
	}
	return x.raw
}

func (a *kubeAction) Describe() string      { return a.desc }
func (a *kubeAction) Policy() policy.Action { return a.policy }
func (a *kubeAction) Target() Text          { return a.target }
func (a *kubeAction) texts() []Text         { return []Text{a.cluster, a.namespace, a.name} }

// render returns the cluster and the request for ev.
func (a *kubeAction) render(ev Event) (string, kubernetes.ActionRequest, error) {
	if a.kube == nil {
		return "", kubernetes.ActionRequest{}, errors.New("this hub runs no Kubernetes integration")
	}
	cluster, err := a.cluster.Render(ev)
	if err != nil {
		return "", kubernetes.ActionRequest{}, err
	}
	req := a.req
	if req.Namespace, err = a.namespace.Render(ev); err != nil {
		return "", kubernetes.ActionRequest{}, err
	}
	if req.Name, err = a.name.Render(ev); err != nil {
		return "", kubernetes.ActionRequest{}, err
	}
	return cluster, req, nil
}

// Run carries the action out. The runtime calls it inside the policy
// decision on it, which RunAction checks.
func (a *kubeAction) Run(ctx context.Context, ev Event) error {
	cluster, req, err := a.render(ev)
	if err != nil {
		return err
	}
	_, err = a.kube.RunAction(ctx, cluster, req)
	if err == nil || errors.Is(err, kubernetes.ErrWriteOutcomeUnknown) || errors.Is(err, kubernetes.ErrDrainIncomplete) {
		return err
	}
	// Whatever else went wrong, no write is left unanswered: the reads an action
	// starts with change nothing, even if they time out.
	return definiteFailure{err}
}

// Plan reads, and changes nothing: what the action would do now, for a
// dry run.
func (a *kubeAction) Plan(ctx context.Context, ev Event) (string, error) {
	cluster, req, err := a.render(ev)
	if err != nil {
		return "", err
	}
	res, err := a.kube.PlanAction(ctx, cluster, req)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(res.Summary)
	for _, s := range res.Steps {
		b.WriteString("\n- " + s)
	}
	for _, w := range res.Warnings {
		b.WriteString("\nwarning: " + w)
	}
	return b.String(), nil
}
