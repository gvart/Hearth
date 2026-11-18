// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"encoding/json"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gvart/hearth/internal/store"
)

func waiting(reason string) corev1.ContainerState {
	return corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}
}

func terminated(reason string, code int32) corev1.ContainerState {
	return corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, ExitCode: code}}
}

var runningState = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}

func TestPodStatus(t *testing.T) {
	now := metav1.Now()
	tests := []struct {
		name string
		pod  corev1.Pod
		want string
	}{
		{"pending", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending}}, "Pending"},
		{"running", corev1.Pod{Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Ready: true, State: runningState}},
		}}, "Running"},
		{"crash loop", corev1.Pod{Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{State: waiting("CrashLoopBackOff")}},
		}}, "CrashLoopBackOff"},
		{"image pull", corev1.Pod{Status: corev1.PodStatus{
			Phase:             corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{State: waiting("ErrImagePull")}},
		}}, "ErrImagePull"},
		{"completed", corev1.Pod{Status: corev1.PodStatus{
			Phase:             corev1.PodSucceeded,
			ContainerStatuses: []corev1.ContainerStatus{{State: terminated("Completed", 0)}},
		}}, "Completed"},
		{"exit code", corev1.Pod{Status: corev1.PodStatus{
			Phase:             corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{{State: terminated("", 3)}},
		}}, "ExitCode:3"},
		{"evicted", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"}}, "Evicted"},
		{"init runningState", corev1.Pod{
			Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: "a"}, {Name: "b"}}},
			Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{
				{State: terminated("Completed", 0)}, {State: runningState},
			}},
		}, "Init:1/2"},
		{"init failing", corev1.Pod{
			Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: "a"}}},
			Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{
				{State: waiting("CrashLoopBackOff")},
			}},
		}, "Init:CrashLoopBackOff"},
		{"terminating", corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}, "Terminating"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := podStatus(&tt.pod); got != tt.want {
				t.Errorf("podStatus = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPodOf(t *testing.T) {
	yes := true
	p := podOf(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "web", Name: "api-1",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api", Controller: &yes}},
		},
		Spec: corev1.PodSpec{NodeName: "pi-1", Containers: []corev1.Container{{Name: "app"}, {Name: "proxy"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.0.5", ContainerStatuses: []corev1.ContainerStatus{
			{Name: "app", Ready: true, RestartCount: 2, State: runningState},
			{Name: "proxy", RestartCount: 1, State: waiting("CrashLoopBackOff")},
		}},
	})
	if p.Ready != "1/2" || p.Restarts != 3 || p.Owner != "ReplicaSet/api" || p.Node != "pi-1" ||
		p.Status != "CrashLoopBackOff" || !slices.Equal(p.Containers, []string{"app", "proxy"}) {
		t.Errorf("podOf = %+v", p)
	}
}

func TestNodeOf(t *testing.T) {
	n := nodeOf(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "talos-cp-1", Labels: map[string]string{
			"node-role.kubernetes.io/control-plane": "", "kubernetes.io/hostname": "talos-cp-1",
		}},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "192.168.2.20"},
				{Type: corev1.NodeHostName, Address: "talos-cp-1"},
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
			NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.34.1", Architecture: "arm64"},
		},
	})
	if !n.Ready || !slices.Equal(n.Roles, []string{"control-plane"}) || n.Hostname != "talos-cp-1" ||
		!slices.Equal(n.Addresses, []string{"192.168.2.20"}) || n.CPU != "4" || n.Memory != "8Gi" || n.Arch != "arm64" {
		t.Errorf("nodeOf = %+v", n)
	}
}

func device(id, hostname string, ips ...string) store.Device {
	facts, _ := json.Marshal(map[string]any{"interfaces": []map[string]any{{"name": "eth0", "ips": ips}}})
	return store.Device{ID: id, Hostname: hostname, Facts: facts}
}

func TestLinkNodeToDevice(t *testing.T) {
	idx := newDeviceIndex([]store.Device{
		device("pi", "pi-1.lan", "192.168.2.131/24", "fe80::1/64"),
		device("nas", "nas", "192.168.2.5/24"),
		device("twin-a", "twin", "192.168.2.50/24"),
		device("twin-b", "twin.lan", "192.168.2.51/24"),
		{ID: "nofacts", Hostname: "bare"},
	})
	tests := []struct {
		name string
		node Node
		want string
	}{
		{"by internal IP", Node{Name: "k3s-agent", Addresses: []string{"192.168.2.131"}}, "pi"},
		{"IP wins over a hostname", Node{Name: "nas", Addresses: []string{"192.168.2.131"}}, "pi"},
		{"by hostname, short form", Node{Name: "x", Hostname: "pi-1", Addresses: []string{"10.0.0.1"}}, "pi"},
		{"by node name", Node{Name: "nas"}, "nas"},
		{"device without facts", Node{Name: "bare.lan"}, "nofacts"},
		{"case insensitive", Node{Name: "NAS"}, "nas"},
		{"ambiguous name links nothing", Node{Name: "twin"}, ""},
		{"no match", Node{Name: "cloud-1", Addresses: []string{"203.0.113.9"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := idx.link(tt.node); got != tt.want {
				t.Errorf("link = %q, want %q", got, tt.want)
			}
		})
	}
}
