// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import "time"

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
