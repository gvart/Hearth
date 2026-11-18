// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
)

// unreachableKubeconfig points at a closed port: the cluster is added and
// then shows as in error.
const unreachableKubeconfig = `apiVersion: v1
kind: Config
current-context: kind-lab
clusters:
- name: kind-lab
  cluster: {server: "https://127.0.0.1:1", insecure-skip-tls-verify: true}
contexts:
- name: kind-lab
  context: {cluster: kind-lab, user: admin}
users:
- name: admin
  user: {token: s3cret-token}
`

func newKubeAPIFixture(t *testing.T) (*httptest.Server, *http.Cookie) {
	t.Helper()
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	sealer, err := kubernetes.NewSealer([]byte("test CA key"))
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.New(st.Audit())
	kube := kubernetes.NewManager(kubernetes.Config{
		Store: st, Sealer: sealer, Policy: pol, Log: log,
		SyncInterval: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = kube.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log}), Kube: kube})
	a.keepalive = time.Hour
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "kube-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return srv, testCookie("kube-session")
}

func TestKubeAPI(t *testing.T) {
	srv, cookie := newKubeAPIFixture(t)
	f := &apiFixture{srv: srv}

	if r := f.do(t, http.MethodGet, "/api/v1/kube/clusters", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list = %d", r.StatusCode)
	}
	if r := f.do(t, http.MethodGet, "/api/v1/kube/clusters", "", cookie); r.StatusCode != http.StatusOK ||
		len(decode[struct{ Clusters []kubernetes.ClusterInfo }](t, r).Clusters) != 0 {
		t.Fatalf("empty list = %d %s", r.StatusCode, r.body)
	}

	// Subscribe before adding, to see the cluster's notices.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/events", nil)
	req.AddCookie(cookie)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	lines := scanLines(resp.Body)
	waitLine := func(prefix string) string {
		t.Helper()
		timeout := time.After(10 * time.Second)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("event stream closed waiting for %q", prefix)
				}
				if strings.HasPrefix(l, prefix) {
					return l
				}
			case <-timeout:
				t.Fatalf("no %q within 10s", prefix)
			}
		}
	}
	waitLine(": subscribed")

	for _, tc := range []struct {
		name, contentType, body string
		want                    int
	}{
		{"not JSON", "text/plain", "x", http.StatusUnsupportedMediaType},
		{"bad body", "application/json", "[]", http.StatusBadRequest},
		{"invalid kubeconfig", "application/json", `{"kubeconfig": "kind: Nope"}`, http.StatusBadRequest},
	} {
		if r := f.send(t, http.MethodPost, "/api/v1/kube/clusters", tc.contentType, tc.body, cookie); r.StatusCode != tc.want {
			t.Errorf("add with %s = %d %s, want %d", tc.name, r.StatusCode, r.body, tc.want)
		}
	}
	body, _ := json.Marshal(map[string]string{"kubeconfig": unreachableKubeconfig})
	r := f.do(t, http.MethodPost, "/api/v1/kube/clusters", string(body), cookie)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("add = %d %s", r.StatusCode, r.body)
	}
	added := decode[kubernetes.ClusterInfo](t, r)
	if added.Name != "kind-lab" || added.ID == "" || strings.Contains(string(r.body), "s3cret") {
		t.Errorf("add = %s", r.body)
	}
	if r := f.do(t, http.MethodPost, "/api/v1/kube/clusters", string(body), cookie); r.StatusCode != http.StatusConflict {
		t.Errorf("add of a taken name = %d, want 409", r.StatusCode)
	}

	// The unreachable cluster's state reaches the event stream.
	waitLine("event: " + kubernetes.NoticeCluster)
	data := waitLine("data: ")
	var info kubernetes.ClusterInfo
	if err := json.Unmarshal([]byte(strings.TrimPrefix(data, "data: ")), &info); err != nil || info.ID != added.ID {
		t.Errorf("kube.cluster event data = %s (%v)", data, err)
	}

	r = f.do(t, http.MethodGet, "/api/v1/kube/clusters/"+added.ID, "", cookie)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("get = %d %s", r.StatusCode, r.body)
	}
	if snap := decode[kubernetes.Snapshot](t, r); snap.Cluster.ID != added.ID || snap.Pods == nil {
		t.Errorf("snapshot = %s", r.body)
	}
	if r := f.do(t, http.MethodGet, "/api/v1/kube/clusters/nope", "", cookie); r.StatusCode != http.StatusNotFound {
		t.Errorf("get unknown = %d", r.StatusCode)
	}
	logs := "/api/v1/kube/clusters/" + added.ID + "/pods/default/web-1/logs"
	if r := f.do(t, http.MethodGet, logs+"?tail=x", "", cookie); r.StatusCode != http.StatusBadRequest {
		t.Errorf("logs with a bad tail = %d", r.StatusCode)
	}
	if r := f.do(t, http.MethodGet, logs, "", cookie); r.StatusCode != http.StatusBadGateway {
		t.Errorf("logs from an unreachable cluster = %d %s, want 502", r.StatusCode, r.body)
	}

	if r := f.do(t, http.MethodDelete, "/api/v1/kube/clusters/"+added.ID, "", cookie); r.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d %s", r.StatusCode, r.body)
	}
	if r := f.do(t, http.MethodDelete, "/api/v1/kube/clusters/"+added.ID, "", cookie); r.StatusCode != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", r.StatusCode)
	}
}

func TestKubeAPIDisabled(t *testing.T) {
	f := newAPIFixture(t, false)
	if err := f.st.Admin().CreateSession(t.Context(), "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := f.do(t, http.MethodGet, "/api/v1/kube/clusters", "", testCookie("s")); r.StatusCode != http.StatusNotFound {
		t.Errorf("list without a manager = %d, want 404", r.StatusCode)
	}
}

// scanLines sends each line read from body until it ends.
func scanLines(body io.Reader) <-chan string {
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	return lines
}
