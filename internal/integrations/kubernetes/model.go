// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"fmt"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// Entity kinds, as the API and events name them.
const (
	KindNode      = "node"
	KindNamespace = "namespace"
	KindWorkload  = "workload"
	KindPod       = "pod"
	KindEvent     = "event"
)

// Node is a Kubernetes node as the API serves it.
type Node struct {
	Name           string    `json:"name"`
	Ready          bool      `json:"ready"`
	Unschedulable  bool      `json:"unschedulable"`
	Roles          []string  `json:"roles"`
	KubeletVersion string    `json:"kubelet_version"`
	OSImage        string    `json:"os_image"`
	Arch           string    `json:"arch"`
	Hostname       string    `json:"hostname"`
	Addresses      []string  `json:"addresses"`
	CPU            string    `json:"cpu"`
	Memory         string    `json:"memory"`
	Created        time.Time `json:"created"`
	// DeviceID is the Hearth device this node runs on, matched by IP
	// address or hostname; "" when none matches.
	DeviceID string `json:"device_id"`
}

// Namespace is a Kubernetes namespace.
type Namespace struct {
	Name    string    `json:"name"`
	Phase   string    `json:"phase"`
	Created time.Time `json:"created"`
}

// Workload is a Deployment, StatefulSet or DaemonSet.
type Workload struct {
	Kind      string    `json:"kind"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Desired   int32     `json:"desired"`
	Ready     int32     `json:"ready"`
	Created   time.Time `json:"created"`
}

// Pod is a Kubernetes pod with a kubectl-style status.
type Pod struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Status is what `kubectl get pods` shows: Running, Pending,
	// CrashLoopBackOff, Completed, Terminating, ...
	Status     string    `json:"status"`
	Phase      string    `json:"phase"`
	Ready      string    `json:"ready"` // ready/total containers
	Restarts   int32     `json:"restarts"`
	Node       string    `json:"node"`
	IP         string    `json:"ip"`
	Owner      string    `json:"owner"` // kind/name of the controller
	Containers []string  `json:"containers"`
	Created    time.Time `json:"created"`
}

// Event is a Kubernetes event (core/v1).
type Event struct {
	UID       string    `json:"uid"`
	Namespace string    `json:"namespace"`
	Type      string    `json:"type"` // Normal or Warning
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	Object    string    `json:"object"` // kind/name
	Count     int32     `json:"count"`
	Last      time.Time `json:"last"`
}

func nodeOf(n *corev1.Node) Node {
	out := Node{
		Name:           n.Name,
		Unschedulable:  n.Spec.Unschedulable,
		KubeletVersion: n.Status.NodeInfo.KubeletVersion,
		OSImage:        n.Status.NodeInfo.OSImage,
		Arch:           n.Status.NodeInfo.Architecture,
		Roles:          []string{},
		Addresses:      []string{},
		Created:        n.CreationTimestamp.UTC(),
	}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			out.Ready = c.Status == corev1.ConditionTrue
		}
	}
	for l := range n.Labels {
		if r, ok := strings.CutPrefix(l, "node-role.kubernetes.io/"); ok && r != "" {
			out.Roles = append(out.Roles, r)
		}
	}
	slices.Sort(out.Roles)
	for _, a := range n.Status.Addresses {
		switch a.Type {
		case corev1.NodeHostName:
			out.Hostname = a.Address
		case corev1.NodeInternalIP, corev1.NodeExternalIP:
			out.Addresses = append(out.Addresses, a.Address)
		}
	}
	if q, ok := n.Status.Capacity[corev1.ResourceCPU]; ok {
		out.CPU = q.String()
	}
	if q, ok := n.Status.Capacity[corev1.ResourceMemory]; ok {
		out.Memory = q.String()
	}
	return out
}

func namespaceOf(n *corev1.Namespace) Namespace {
	return Namespace{Name: n.Name, Phase: string(n.Status.Phase), Created: n.CreationTimestamp.UTC()}
}

func deploymentOf(d *appsv1.Deployment) Workload {
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	return Workload{
		Kind: "Deployment", Namespace: d.Namespace, Name: d.Name,
		Desired: desired, Ready: d.Status.ReadyReplicas, Created: d.CreationTimestamp.UTC(),
	}
}

func statefulSetOf(s *appsv1.StatefulSet) Workload {
	desired := int32(1)
	if s.Spec.Replicas != nil {
		desired = *s.Spec.Replicas
	}
	return Workload{
		Kind: "StatefulSet", Namespace: s.Namespace, Name: s.Name,
		Desired: desired, Ready: s.Status.ReadyReplicas, Created: s.CreationTimestamp.UTC(),
	}
}

func daemonSetOf(d *appsv1.DaemonSet) Workload {
	return Workload{
		Kind: "DaemonSet", Namespace: d.Namespace, Name: d.Name,
		Desired: d.Status.DesiredNumberScheduled, Ready: d.Status.NumberReady, Created: d.CreationTimestamp.UTC(),
	}
}

func podOf(p *corev1.Pod) Pod {
	out := Pod{
		Namespace:  p.Namespace,
		Name:       p.Name,
		Phase:      string(p.Status.Phase),
		Node:       p.Spec.NodeName,
		IP:         p.Status.PodIP,
		Containers: make([]string, 0, len(p.Spec.Containers)),
		Created:    p.CreationTimestamp.UTC(),
	}
	for _, c := range p.Spec.Containers {
		out.Containers = append(out.Containers, c.Name)
	}
	for _, o := range p.OwnerReferences {
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
func podStatus(p *corev1.Pod) string {
	reason := string(p.Status.Phase)
	if p.Status.Reason != "" {
		reason = p.Status.Reason
	}
	for i, cs := range p.Status.InitContainerStatuses {
		switch {
		case cs.State.Terminated != nil && cs.State.Terminated.ExitCode == 0:
			continue
		case cs.State.Terminated != nil:
			if cs.State.Terminated.Reason != "" {
				return "Init:" + cs.State.Terminated.Reason
			}
			return fmt.Sprintf("Init:ExitCode:%d", cs.State.Terminated.ExitCode)
		case cs.State.Waiting != nil && cs.State.Waiting.Reason != "" && cs.State.Waiting.Reason != "PodInitializing":
			return "Init:" + cs.State.Waiting.Reason
		default:
			return fmt.Sprintf("Init:%d/%d", i, len(p.Spec.InitContainers))
		}
	}
	running := false
	for _, cs := range p.Status.ContainerStatuses {
		switch {
		case cs.State.Waiting != nil && cs.State.Waiting.Reason != "":
			reason = cs.State.Waiting.Reason
		case cs.State.Terminated != nil && cs.State.Terminated.Reason != "":
			reason = cs.State.Terminated.Reason
		case cs.State.Terminated != nil:
			reason = fmt.Sprintf("ExitCode:%d", cs.State.Terminated.ExitCode)
		case cs.Ready && cs.State.Running != nil:
			running = true
		}
	}
	if reason == "Completed" && running {
		reason = string(corev1.PodRunning)
	}
	if p.DeletionTimestamp != nil {
		if p.Status.Reason == "NodeLost" {
			return "Unknown"
		}
		return "Terminating"
	}
	return reason
}

func eventOf(e *corev1.Event) Event {
	last := e.LastTimestamp.Time
	if last.IsZero() {
		last = e.EventTime.Time
	}
	if last.IsZero() {
		last = e.CreationTimestamp.Time
	}
	count := e.Count
	if e.Series != nil && e.Series.Count > count {
		count = e.Series.Count
	}
	return Event{
		UID: string(e.UID), Namespace: e.Namespace, Type: e.Type, Reason: e.Reason, Message: e.Message,
		Object: strings.ToLower(e.InvolvedObject.Kind) + "/" + e.InvolvedObject.Name,
		Count:  count, Last: last.UTC(),
	}
}
