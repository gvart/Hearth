// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
)

// KubeNodes reads the Nodes of the clusters the hub adopted, by cluster
// name, for a runbook's kube_node checks: *kubernetes.Manager. NodeReady
// must not audit: the engine runs it inside its own policy decision on
// policy.KubeNodeReady, and it refuses to run outside one.
type KubeNodes interface {
	// NodeReady returns nil if the node is Ready; an error wrapping
	// kubernetes.ErrNotFound if the hub has no such cluster.
	NodeReady(ctx context.Context, cluster, node string) error
}

// errNoKubeNodes fails a kube_node check on a hub that cannot run one.
var errNoKubeNodes = errors.New("this hub runs no Kubernetes integration")

// kubeNodeCheck is a check that a Node of an adopted cluster is Ready, read by
// the hub through the cluster's kubeconfig.
type kubeNodeCheck struct {
	cluster, node string
}

// run reads the node once. ran is false when the check cannot run at all:
// the hub has not adopted the cluster. A node that is not there yet fails the
// check like a node that is not Ready: it may be about to register.
func (k *kubeNodeCheck) run(ctx context.Context, nodes KubeNodes) (ran bool, err error) {
	err = nodes.NodeReady(ctx, k.cluster, k.node)
	if errors.Is(err, kubernetes.ErrNotFound) {
		return false, err
	}
	return true, err
}

// buildKubeNodeCheck builds a runbook's kube_node check. It runs from the hub
// only: it has no from.
func buildKubeNodeCheck(p Params) (Trigger, error) {
	var cfg struct {
		Cluster string `yaml:"cluster"`
		Node    string `yaml:"node"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Cluster == "" {
		return nil, errors.New("cluster is required: the name of a cluster the hub adopted")
	}
	if !kubernetes.ValidNodeName(cfg.Node) {
		return nil, errors.New("node must be a Kubernetes node name")
	}
	return &checkTrigger{
		what:     fmt.Sprintf("Kubernetes node %s in cluster %s is Ready", cfg.Node, cfg.Cluster),
		target:   cfg.Cluster + "/" + cfg.Node,
		kubeNode: &kubeNodeCheck{cluster: cfg.Cluster, node: cfg.Node},
	}, nil
}
