// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import "time"

// The Kubernetes API objects the hub reads, reduced to the fields it uses.
// encoding/json ignores the rest. They are hand-written rather than taken
// from k8s.io/api: client-go and its API types would grow the one hearth
// binary by about 9 MB and every idle agent by about 4 MB of RSS (their
// package inits fault in code pages), past the agent's 25 MB budget.

type objectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp"`
	Labels            map[string]string `json:"labels"`
	OwnerReferences   []ownerReference  `json:"ownerReferences"`
}

type ownerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller"`
}

// listMeta is the metadata of a list, and the object of a watch BOOKMARK.
type listMeta struct {
	ResourceVersion string `json:"resourceVersion"`
}

type node struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Unschedulable bool `json:"unschedulable"`
	} `json:"spec"`
	Status struct {
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		Addresses []struct {
			Type    string `json:"type"`
			Address string `json:"address"`
		} `json:"addresses"`
		Capacity map[string]string `json:"capacity"`
		NodeInfo struct {
			KubeletVersion string `json:"kubeletVersion"`
			OSImage        string `json:"osImage"`
			Architecture   string `json:"architecture"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

type namespace struct {
	Metadata objectMeta `json:"metadata"`
	Status   struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type container struct {
	Name string `json:"name"`
}

type containerState struct {
	Waiting *struct {
		Reason string `json:"reason"`
	} `json:"waiting"`
	Running *struct {
		StartedAt time.Time `json:"startedAt"`
	} `json:"running"`
	Terminated *struct {
		Reason   string `json:"reason"`
		ExitCode int32  `json:"exitCode"`
	} `json:"terminated"`
}

type containerStatus struct {
	Name         string         `json:"name"`
	Ready        bool           `json:"ready"`
	RestartCount int32          `json:"restartCount"`
	State        containerState `json:"state"`
}

type pod struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		NodeName       string      `json:"nodeName"`
		Containers     []container `json:"containers"`
		InitContainers []container `json:"initContainers"`
	} `json:"spec"`
	Status struct {
		Phase                 string            `json:"phase"`
		Reason                string            `json:"reason"`
		PodIP                 string            `json:"podIP"`
		ContainerStatuses     []containerStatus `json:"containerStatuses"`
		InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type event struct {
	Metadata       objectMeta `json:"metadata"`
	InvolvedObject struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"involvedObject"`
	Type          string    `json:"type"`
	Reason        string    `json:"reason"`
	Message       string    `json:"message"`
	Count         int32     `json:"count"`
	LastTimestamp time.Time `json:"lastTimestamp"`
	EventTime     time.Time `json:"eventTime"`
	Series        *struct {
		Count int32 `json:"count"`
	} `json:"series"`
}

// replicated is a Deployment or a StatefulSet.
type replicated struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Replicas *int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas int32 `json:"readyReplicas"`
	} `json:"status"`
}

type daemonSet struct {
	Metadata objectMeta `json:"metadata"`
	Status   struct {
		DesiredNumberScheduled int32 `json:"desiredNumberScheduled"`
		NumberReady            int32 `json:"numberReady"`
	} `json:"status"`
}

// status is a metav1.Status: an API error, or the object of a watch ERROR.
type status struct {
	Message string `json:"message"`
	Reason  string `json:"reason"`
	Code    int    `json:"code"`
}
