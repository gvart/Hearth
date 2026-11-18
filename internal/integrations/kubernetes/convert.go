// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"fmt"
	"slices"
	"strings"
)

func nodeOf(n *node) Node {
	out := Node{
		Name:           n.Metadata.Name,
		Unschedulable:  n.Spec.Unschedulable,
		KubeletVersion: n.Status.NodeInfo.KubeletVersion,
		OSImage:        n.Status.NodeInfo.OSImage,
		Arch:           n.Status.NodeInfo.Architecture,
		Roles:          []string{},
		Addresses:      []string{},
		CPU:            n.Status.Capacity["cpu"],
		Memory:         n.Status.Capacity["memory"],
		Created:        n.Metadata.CreationTimestamp.UTC(),
	}
	for _, c := range n.Status.Conditions {
		if c.Type == "Ready" {
			out.Ready = c.Status == "True"
		}
	}
	for l := range n.Metadata.Labels {
		if r, ok := strings.CutPrefix(l, "node-role.kubernetes.io/"); ok && r != "" {
			out.Roles = append(out.Roles, r)
		}
	}
	slices.Sort(out.Roles)
	for _, a := range n.Status.Addresses {
		switch a.Type {
		case "Hostname":
			out.Hostname = a.Address
		case "InternalIP", "ExternalIP":
			out.Addresses = append(out.Addresses, a.Address)
		}
	}
	return out
}

func namespaceOf(n *namespace) Namespace {
	return Namespace{Name: n.Metadata.Name, Phase: n.Status.Phase, Created: n.Metadata.CreationTimestamp.UTC()}
}

func replicatedOf(kind string, r *replicated) Workload {
	desired := int32(1)
	if r.Spec.Replicas != nil {
		desired = *r.Spec.Replicas
	}
	return Workload{
		Kind: kind, Namespace: r.Metadata.Namespace, Name: r.Metadata.Name,
		Desired: desired, Ready: r.Status.ReadyReplicas, Created: r.Metadata.CreationTimestamp.UTC(),
	}
}

func daemonSetOf(d *daemonSet) Workload {
	return Workload{
		Kind: "DaemonSet", Namespace: d.Metadata.Namespace, Name: d.Metadata.Name,
		Desired: d.Status.DesiredNumberScheduled, Ready: d.Status.NumberReady, Created: d.Metadata.CreationTimestamp.UTC(),
	}
}

func podOf(p *pod) Pod {
	out := Pod{
		Namespace:  p.Metadata.Namespace,
		Name:       p.Metadata.Name,
		Phase:      p.Status.Phase,
		Node:       p.Spec.NodeName,
		IP:         p.Status.PodIP,
		Containers: make([]string, 0, len(p.Spec.Containers)),
		Created:    p.Metadata.CreationTimestamp.UTC(),
	}
	for _, c := range p.Spec.Containers {
		out.Containers = append(out.Containers, c.Name)
	}
	for _, o := range p.Metadata.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			out.Owner = o.Kind + "/" + o.Name
		}
	}
	ready := 0
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Ready {
			ready++
		}
		out.Restarts += cs.RestartCount
	}
	out.Ready = fmt.Sprintf("%d/%d", ready, len(p.Spec.Containers))
	out.Status = podStatus(p)
	return out
}

// podStatus approximates the STATUS column of `kubectl get pods`.
func podStatus(p *pod) string {
	reason := p.Status.Phase
	if p.Status.Reason != "" {
		reason = p.Status.Reason
	}
	for i, cs := range p.Status.InitContainerStatuses {
		st := cs.State
		switch {
		case st.Terminated != nil && st.Terminated.ExitCode == 0:
			continue
		case st.Terminated != nil:
			if st.Terminated.Reason != "" {
				return "Init:" + st.Terminated.Reason
			}
			return fmt.Sprintf("Init:ExitCode:%d", st.Terminated.ExitCode)
		case st.Waiting != nil && st.Waiting.Reason != "" && st.Waiting.Reason != "PodInitializing":
			return "Init:" + st.Waiting.Reason
		default:
			return fmt.Sprintf("Init:%d/%d", i, len(p.Spec.InitContainers))
		}
	}
	running := false
	for _, cs := range p.Status.ContainerStatuses {
		st := cs.State
		switch {
		case st.Waiting != nil && st.Waiting.Reason != "":
			reason = st.Waiting.Reason
		case st.Terminated != nil && st.Terminated.Reason != "":
			reason = st.Terminated.Reason
		case st.Terminated != nil:
			reason = fmt.Sprintf("ExitCode:%d", st.Terminated.ExitCode)
		case cs.Ready && st.Running != nil:
			running = true
		}
	}
	if reason == "Completed" && running {
		reason = "Running"
	}
	if p.Metadata.DeletionTimestamp != nil {
		if p.Status.Reason == "NodeLost" {
			return "Unknown"
		}
		return "Terminating"
	}
	return reason
}

func eventOf(e *event) Event {
	last := e.LastTimestamp
	if last.IsZero() {
		last = e.EventTime
	}
	if last.IsZero() {
		last = e.Metadata.CreationTimestamp
	}
	count := e.Count
	if e.Series != nil && e.Series.Count > count {
		count = e.Series.Count
	}
	return Event{
		UID: e.Metadata.UID, Namespace: e.Metadata.Namespace, Type: e.Type, Reason: e.Reason, Message: e.Message,
		Object: strings.ToLower(e.InvolvedObject.Kind) + "/" + e.InvolvedObject.Name,
		Count:  count, Last: last.UTC(),
	}
}
