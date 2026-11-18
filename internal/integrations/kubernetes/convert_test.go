// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/gvart/hearth/internal/store"
)

func mustPod(t *testing.T, js string) *pod {
	t.Helper()
	var p pod
	if err := json.Unmarshal([]byte(js), &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestPodStatus(t *testing.T) {
	tests := []struct{ name, pod, want string }{
		{"pending", `{"status":{"phase":"Pending"}}`, "Pending"},
		{"running", `{"status":{"phase":"Running","containerStatuses":[{"ready":true,"state":{"running":{}}}]}}`, "Running"},
		{"crash loop", `{"status":{"phase":"Running","containerStatuses":[{"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`, "CrashLoopBackOff"},
		{"image pull", `{"status":{"phase":"Pending","containerStatuses":[{"state":{"waiting":{"reason":"ErrImagePull"}}}]}}`, "ErrImagePull"},
		{"completed", `{"status":{"phase":"Succeeded","containerStatuses":[{"state":{"terminated":{"reason":"Completed"}}}]}}`, "Completed"},
		{"exit code", `{"status":{"phase":"Failed","containerStatuses":[{"state":{"terminated":{"exitCode":3}}}]}}`, "ExitCode:3"},
		{"evicted", `{"status":{"phase":"Failed","reason":"Evicted"}}`, "Evicted"},
		{"init running", `{"spec":{"initContainers":[{"name":"a"},{"name":"b"}]},"status":{"phase":"Pending",
			"initContainerStatuses":[{"state":{"terminated":{"reason":"Completed","exitCode":0}}},{"state":{"running":{}}}]}}`, "Init:1/2"},
		{"init failing", `{"spec":{"initContainers":[{"name":"a"}]},"status":{"phase":"Pending",
			"initContainerStatuses":[{"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`, "Init:CrashLoopBackOff"},
		{"terminating", `{"metadata":{"deletionTimestamp":"2026-11-18T10:00:00Z"},"status":{"phase":"Running"}}`, "Terminating"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := podStatus(mustPod(t, tt.pod)); got != tt.want {
				t.Errorf("podStatus = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPodOf(t *testing.T) {
	p := podOf(mustPod(t, `{
		"metadata": {"namespace": "web", "name": "api-1",
			"ownerReferences": [{"kind": "ReplicaSet", "name": "api", "controller": true}]},
		"spec": {"nodeName": "pi-1", "containers": [{"name": "app"}, {"name": "proxy"}]},
		"status": {"phase": "Running", "podIP": "10.42.0.5", "containerStatuses": [
			{"name": "app", "ready": true, "restartCount": 2, "state": {"running": {}}},
			{"name": "proxy", "restartCount": 1, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}}`))
	if p.Ready != "1/2" || p.Restarts != 3 || p.Owner != "ReplicaSet/api" || p.Node != "pi-1" || p.IP != "10.42.0.5" ||
		p.Status != "CrashLoopBackOff" || !slices.Equal(p.Containers, []string{"app", "proxy"}) {
		t.Errorf("podOf = %+v", p)
	}
}

func TestNodeOf(t *testing.T) {
	b, _ := json.Marshal(nodeObj("talos-cp-1", "192.168.2.20", true))
	var n node
	if err := json.Unmarshal(b, &n); err != nil {
		t.Fatal(err)
	}
	got := nodeOf(&n)
	if !got.Ready || !slices.Equal(got.Roles, []string{"control-plane"}) || got.Hostname != "talos-cp-1" ||
		!slices.Equal(got.Addresses, []string{"192.168.2.20"}) || got.CPU != "4" || got.Memory != "8Gi" || got.Arch != "arm64" {
		t.Errorf("nodeOf = %+v", got)
	}
}

func TestEventOf(t *testing.T) {
	var e event
	if err := json.Unmarshal([]byte(`{"metadata":{"uid":"u1","namespace":"default","creationTimestamp":"2026-11-18T10:00:00Z"},
		"involvedObject":{"kind":"Pod","name":"web-1"},"type":"Warning","reason":"BackOff","count":2,
		"lastTimestamp":null,"eventTime":"2026-11-18T10:05:00.123456Z","series":{"count":7}}`), &e); err != nil {
		t.Fatal(err)
	}
	got := eventOf(&e)
	if got.Object != "pod/web-1" || got.Count != 7 || got.Last.Minute() != 5 || got.UID != "u1" {
		t.Errorf("eventOf = %+v", got)
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
