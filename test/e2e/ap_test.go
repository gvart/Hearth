// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Time bounds of the AP cluster test (ap.compose.yaml). Never raise one to
// make CI pass.
const (
	// APFormationWithin bounds forming the AP cluster: three container
	// starts and two joins, until every hub sees 3 live storage members.
	APFormationWithin = 60 * time.Second
	// APWritesWithin bounds how long after a hub is killed a critical write
	// (an enrollment token: the token row and its audit entry) works on the
	// survivors: none at all should be needed, a replica that does not
	// answer is replaced by a stand-in at once.
	APWritesWithin = 5 * time.Second
	// APConvergeWithin bounds how long after a partition heals every hub
	// answers the same queries byte for byte: failure detection, hints and
	// an anti-entropy round (every 10 s).
	APConvergeWithin = 45 * time.Second
)

var apHubs = []string{"hub-a", "hub-b", "hub-c"}

// TestAPCluster guards the AP cluster (--cluster-mode ap, N=2, every hub
// master and storage): a hub killed loses no acknowledged critical write and
// the devices stay listed; a partition healed converges to byte-identical
// query results on every hub.
func TestAPCluster(t *testing.T) {
	ctx := t.Context()
	s := newStack(t, "hearth-e2e-ap", "ap.compose.yaml", append(apHubs[:3:3], agentName))
	s.compose(ctx, "build")

	// 1. hub-a forms the cluster alone; hub-b and hub-c join it.
	formAt := time.Now()
	s.compose(ctx, "up", "--detach", "--wait", "--wait-timeout", "60", "hub-a", agentName)
	for _, h := range apHubs[1:] {
		tok := s.clusterJoinToken(ctx, "hub-a", formAt.Add(APFormationWithin))
		s.composeEnv(ctx, []string{"HEARTH_JOIN_TOKEN=" + tok},
			"up", "--detach", "--no-deps", "--wait", "--wait-timeout", "60", h)
	}
	s.waitAPMembers(ctx, apHubs, apHubs, formAt.Add(APFormationWithin))
	t.Logf("TIMING AP formation: 3 storage members, N=2, in %v", since(formAt))

	apis := map[string]*apiClient{}
	for _, h := range apHubs {
		apis[h] = s.loginTo(ctx, h)
	}

	// 2. Enroll the agent: token from hub-b, join through hub-c. Every hub
	// lists it online within the headline bound.
	token := apis["hub-b"].createToken(ctx)
	joinAt := time.Now()
	s.compose(ctx, "exec", "-T", agentName, "hearth", "agent", "join", "https://hub-c:7443", token, "--data-dir", agentDataDir)
	s.startAgent(ctx, agentName)
	for _, h := range apHubs {
		apis[h].waitDevice(ctx, agentName, joinAt.Add(DeviceVisibleWithin), "online on "+h, func(d device) bool {
			return d.Status == "online"
		})
	}
	t.Logf("TIMING enroll → online on every hub in %v", since(joinAt))

	// 3. Critical writes on every hub, then kill hub-c. Every acknowledged
	// audit entry is still on the survivors, the device is still listed,
	// and critical writes go on.
	for i := range 9 {
		apis[apHubs[i%3]].createToken(ctx)
	}
	acked := apis["hub-a"].auditIDs(ctx)
	killAt := time.Now()
	s.compose(ctx, "kill", "--signal", "SIGKILL", "hub-c")
	survivors := apHubs[:2]
	for _, h := range survivors {
		got := apis[h].auditIDs(ctx)
		for id := range acked {
			if !got[id] {
				t.Errorf("audit entry %d acknowledged before the kill is missing on %s", id, h)
			}
		}
		if devs, err := apis[h].devices(ctx); err != nil || !hasHost(devs, agentName) {
			t.Errorf("devices on %s after the kill: %v, %v", h, devs, err)
		}
	}
	for _, h := range survivors {
		waitFor(ctx, t, killAt.Add(APWritesWithin), "a critical write on "+h, func() (bool, string) {
			status, code, err := apis[h].postStatus(ctx, "/api/v1/tokens", map[string]string{"ttl": "5m"})
			if err != nil {
				return false, err.Error()
			}
			return status == http.StatusCreated, fmt.Sprintf("%d %s", status, code)
		})
	}
	t.Logf("TIMING kill hub-c → no acknowledged write lost, critical writes on both survivors in %v", since(killAt))

	// 4. hub-c back; the agent stops, so nothing changes but what the test
	// writes. Cut hub-a off, write on both sides, heal.
	s.compose(ctx, "start", "hub-c")
	s.waitAPMembers(ctx, apHubs, apHubs, time.Now().Add(APFormationWithin))
	apis["hub-c"] = s.loginTo(ctx, "hub-c")
	s.compose(ctx, "exec", "-T", agentName, "pkill", "-f", "hearth agent run")

	s.network(ctx, "disconnect", "hub-a")
	splitAt := time.Now()
	s.waitAPMembers(ctx, []string{"hub-b", "hub-c"}, []string{"hub-b", "hub-c"}, splitAt.Add(30*time.Second))
	for range 3 {
		apis["hub-b"].createToken(ctx)
		apis["hub-c"].createToken(ctx)
		// hub-a alone takes what does not need a second replica, and refuses
		// a critical write fast, with 503.
		if status, code, err := apis["hub-a"].postStatus(ctx, "/api/v1/tokens", map[string]string{"ttl": "5m"}); err == nil &&
			status != http.StatusCreated && (status != http.StatusServiceUnavailable || code != "cluster_unavailable") {
			t.Errorf("critical write on the cut-off hub-a: %d %s", status, code)
		}
	}
	s.network(ctx, "connect", "hub-a")
	healAt := time.Now()
	waitFor(ctx, t, healAt.Add(APConvergeWithin), "byte-identical answers on every hub", func() (bool, string) {
		for _, path := range []string{"/api/v1/devices", "/api/v1/audit?limit=500"} {
			var first []byte
			for _, h := range apHubs {
				b, err := apis[h].raw(ctx, path)
				if err != nil {
					return false, h + ": " + err.Error()
				}
				if first == nil {
					first = b
				} else if !bytes.Equal(first, b) {
					return false, path + " differs on " + h
				}
			}
		}
		return true, ""
	})
	t.Logf("TIMING heal → byte-identical devices and audit on every hub in %v", since(healAt))
}

// waitAPMembers waits until every one of hubs sees each of alive as a live
// member, and says it is highly available.
func (s *stack) waitAPMembers(ctx context.Context, hubs, alive []string, deadline time.Time) {
	s.t.Helper()
	waitFor(ctx, s.t, deadline, strings.Join(alive, ", ")+" alive on "+strings.Join(hubs, ", "), func() (bool, string) {
		for _, h := range hubs {
			out, err := s.run(ctx, "exec", "-T", h, "hearth", "cluster", "status", "--json", "--data-dir", hubDataDir)
			if err != nil {
				return false, err.Error()
			}
			var st struct {
				Mode            string `json:"mode"`
				HighlyAvailable bool   `json:"highly_available"`
				Members         []struct {
					ID    string `json:"id"`
					State string `json:"state"`
				} `json:"members"`
			}
			if err := json.Unmarshal([]byte(out), &st); err != nil {
				return false, err.Error()
			}
			if st.Mode != "ap" || !st.HighlyAvailable {
				return false, fmt.Sprintf("%s: mode %q, highly available %v", h, st.Mode, st.HighlyAvailable)
			}
			states := map[string]string{}
			for _, m := range st.Members {
				states[m.ID] = m.State
			}
			for _, a := range alive {
				if states[a] != "alive" {
					return false, fmt.Sprintf("%s sees %s %q", h, a, states[a])
				}
			}
		}
		return true, ""
	})
}

// network connects the service's container to the project network, or
// disconnects it.
func (s *stack) network(ctx context.Context, op, service string) {
	s.t.Helper()
	id := strings.TrimSpace(s.compose(ctx, "ps", "--all", "--quiet", service))
	if out, err := exec.CommandContext(ctx, "docker", "network", op, s.project+"_default", id).CombinedOutput(); err != nil {
		s.t.Fatalf("network %s %s: %v\n%s", op, service, err, out)
	}
}

// auditIDs returns the ids of every audit entry.
func (c *apiClient) auditIDs(ctx context.Context) map[int64]bool {
	c.t.Helper()
	out := map[int64]bool{}
	path := "/api/v1/audit?limit=500"
	for {
		b, err := c.raw(ctx, path)
		if err != nil {
			c.t.Fatalf("audit: %v", err)
		}
		var page struct {
			Entries []struct {
				ID int64 `json:"id"`
			} `json:"entries"`
			NextBefore int64 `json:"next_before"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			c.t.Fatalf("audit: %v", err)
		}
		for _, e := range page.Entries {
			out[e.ID] = true
		}
		if page.NextBefore == 0 || len(page.Entries) == 0 {
			return out
		}
		path = "/api/v1/audit?limit=500&before=" + strconv.FormatInt(page.NextBefore, 10)
	}
}

// raw GETs path and returns the body.
func (c *apiClient) raw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return b, nil
}

func hasHost(devs []device, host string) bool {
	for _, d := range devs {
		if d.Hostname == host {
			return true
		}
	}
	return false
}
