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
	"net/url"
	"os/exec"
	"slices"
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
	// an anti-entropy round (every 30 s).
	APConvergeWithin = 60 * time.Second
)

var apHubs = []string{"hub-a", "hub-b", "hub-c"}

// TestAPCluster guards the AP cluster (--cluster-mode ap, N=2, every hub
// master and storage): a hub killed loses no acknowledged critical write and
// the devices stay listed; a partition healed converges to byte-identical
// query results on every hub.
func TestAPCluster(t *testing.T) {
	ctx := t.Context()
	s := newStack(t, "hearth-e2e-ap", "ap.compose.yaml", append(apHubs[:3:3], "hub-d", agentName))
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

	// 2. Enroll the agent: token from hub-b, join through hub-c. The token
	// names hub-b, its owner, and the agent enrolls there. Every hub lists
	// it online within the headline bound.
	token := apis["hub-b"].createToken(ctx)
	if !strings.HasPrefix(token, "hearth2.") {
		t.Fatalf("token from an AP master is not a hearth2 token naming its owner")
	}
	joinAt := time.Now()
	s.compose(ctx, "exec", "-T", agentName, "hearth", "agent", "join", "https://hub-c:7443", token, "--data-dir", agentDataDir)
	s.startAgent(ctx, agentName)
	for _, h := range apHubs {
		apis[h].waitDevice(ctx, agentName, joinAt.Add(DeviceVisibleWithin), "online on "+h, func(d device) bool {
			return d.Status == "online"
		})
	}
	t.Logf("TIMING enroll (token naming its owner hub-b) → online on every hub in %v", since(joinAt))

	// The token is spent: used again on another master, even in its
	// hearth1 form that names no owner, it is refused.
	parts := strings.Split(token, ".")
	for _, tok := range []string{token, "hearth1." + parts[1] + "." + parts[2]} {
		if out, err := s.run(ctx, "exec", "-T", agentName, "hearth", "agent", "join", "https://hub-a:7443", tok,
			"--data-dir", "/tmp/reuse"); err == nil {
			t.Errorf("a spent token enrolled again through hub-a:\n%s", out)
		}
	}

	// 2b. Kill the master the agent streams to (the first of its hubs): the
	// agent is on another master, and the device online there, within the
	// headline bound.
	streamHub := s.agentStreamHub(ctx)
	killAt := time.Now()
	s.compose(ctx, "kill", "--signal", "SIGKILL", streamHub)
	killedAt := s.finishedAt(ctx, streamHub)
	var movedTo string
	waitFor(ctx, t, killAt.Add(DeviceVisibleWithin), "the agent on another master", func() (bool, string) {
		movedTo = s.agentStreamHub(ctx)
		return movedTo != streamHub && slices.Contains(apHubs, movedTo), "on " + movedTo
	})
	apis[movedTo].waitDevice(ctx, agentName, killAt.Add(DeviceVisibleWithin), "online on "+movedTo, func(d device) bool {
		return d.Status == "online" && d.LastSeen.After(killedAt)
	})
	t.Logf("TIMING kill %s (the agent's stream) → agent on %s and online in %v", streamHub, movedTo, since(killAt))
	s.compose(ctx, "start", streamHub)
	s.waitAPMembers(ctx, apHubs, apHubs, time.Now().Add(APFormationWithin))
	apis[streamHub] = s.loginTo(ctx, streamHub)

	// 3. Critical writes on every hub, then kill hub-c. Every acknowledged
	// audit entry is still on the survivors, the device is still listed,
	// and critical writes go on.
	for i := range 9 {
		apis[apHubs[i%3]].createToken(ctx)
	}
	acked := apis["hub-a"].auditIDs(ctx)
	killAt = time.Now()
	s.compose(ctx, "kill", "--signal", "SIGKILL", "hub-c")
	survivors := apHubs[:2]
	for _, h := range survivors {
		got := apis[h].auditIDs(ctx)
		for id, what := range acked {
			if _, ok := got[id]; !ok {
				t.Errorf("audit entry %s (%s) acknowledged before the kill is missing on %s", id, what, h)
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
	}
	// hub-a alone refuses a critical write (a token and its audit entry need
	// two replicas). Its published API port went with the network, so the
	// CLI on its host asks.
	refuseAt := time.Now()
	if out, err := s.run(ctx, "exec", "-T", "hub-a", "hearth", "token", "create", "--data-dir", hubDataDir); err == nil {
		t.Errorf("critical write on the cut-off hub-a succeeded:\n%s", out)
	} else if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("critical write on the cut-off hub-a: %v, want cluster unavailable", err)
	}
	t.Logf("TIMING critical write on the cut-off hub-a refused in %v", since(refuseAt))
	s.network(ctx, "connect", "hub-a")
	healAt := time.Now()
	apis["hub-a"] = s.loginTo(ctx, "hub-a")
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

	// 5. A fourth member: hub-d joins (master and storage), is demoted from
	// storage by the CLI on hub-a (its rows handed off), then promoted back
	// by the API of hub-b: syncing until it holds its rows again.
	all := append(apHubs[:3:3], "hub-d")
	tok := s.clusterJoinToken(ctx, "hub-a", time.Now().Add(APFormationWithin))
	s.composeEnv(ctx, []string{"HEARTH_JOIN_TOKEN=" + tok}, "up", "--detach", "--no-deps", "--wait", "--wait-timeout", "60", "hub-d")
	s.waitAPMembers(ctx, all, all, time.Now().Add(APFormationWithin))
	demoteAt := time.Now()
	s.compose(ctx, "exec", "-T", "hub-a", "hearth", "cluster", "demote", "hub-d", "storage", "--data-dir", hubDataDir)
	waitFor(ctx, t, demoteAt.Add(APConvergeWithin), "hub-d drained and out of storage", func() (bool, string) {
		m := s.apMember(ctx, "hub-a", "hub-d")
		return !slices.Contains(m.Roles, "storage") && !m.Draining, fmt.Sprintf("%+v", m)
	})
	t.Logf("TIMING demote hub-d from storage → drained in %v", since(demoteAt))
	promoteAt := time.Now()
	if status, code, err := apis["hub-b"].postStatus(ctx, "/api/v1/cluster/members/hub-d/promote",
		map[string]string{"role": "storage"}); err != nil || status != http.StatusOK {
		t.Fatalf("promote hub-d to storage: %d %s %v", status, code, err)
	}
	waitFor(ctx, t, promoteAt.Add(APConvergeWithin), "hub-d in sync", func() (bool, string) {
		m := s.apMember(ctx, "hub-a", "hub-d")
		return slices.Contains(m.Roles, "storage") && !m.Syncing, fmt.Sprintf("%+v", m)
	})
	t.Logf("TIMING promote hub-d to storage → synced in %v", since(promoteAt))
	apis["hub-d"] = s.loginTo(ctx, "hub-d")
	for _, path := range []string{"/api/v1/devices", "/api/v1/audit?limit=500"} {
		want, err := apis["hub-a"].raw(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := apis["hub-d"].raw(ctx, path); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s on hub-d after its catch-up differs from hub-a's (%v)", path, err)
		}
	}

	// 6. Demote the master the agent streams to, through another master's
	// API: the agent is on another master and the device online there
	// within the headline bound.
	s.startAgent(ctx, agentName)
	apis["hub-a"].waitDevice(ctx, agentName, time.Now().Add(DeviceVisibleWithin), "online again", func(d device) bool {
		return d.Status == "online"
	})
	streamHub = s.agentStreamHub(ctx)
	other := "hub-a"
	if streamHub == other {
		other = "hub-b"
	}
	demoteAt = time.Now()
	if status, code, err := apis[other].postStatus(ctx, "/api/v1/cluster/members/"+streamHub+"/demote",
		map[string]string{"role": "master"}); err != nil || status != http.StatusOK {
		t.Fatalf("demote %s from master: %d %s %v", streamHub, status, code, err)
	}
	waitFor(ctx, t, demoteAt.Add(DeviceVisibleWithin), "the agent on another master", func() (bool, string) {
		movedTo = s.agentStreamHub(ctx)
		return movedTo != streamHub && slices.Contains(all, movedTo), "on " + movedTo
	})
	apis[movedTo].waitDevice(ctx, agentName, demoteAt.Add(DeviceVisibleWithin), "online on "+movedTo, func(d device) bool {
		return d.Status == "online" && d.LastSeen.After(demoteAt)
	})
	t.Logf("TIMING demote %s (the agent's stream) from master → agent on %s and online in %v", streamHub, movedTo, since(demoteAt))
	if out, err := s.run(ctx, "exec", "-T", streamHub, "test", "-e", hubDataDir+"/ca.key"); err == nil {
		t.Errorf("the demoted %s still holds the CA key:\n%s", streamHub, out)
	}
}

// apMemberInfo is a member as `hearth cluster status --json` shows it.
type apMemberInfo struct {
	ID       string   `json:"id"`
	State    string   `json:"state"`
	Roles    []string `json:"roles"`
	Syncing  bool     `json:"syncing"`
	Draining bool     `json:"draining"`
	Progress int      `json:"progress"`
}

// apMember is member id as hub sees it.
func (s *stack) apMember(ctx context.Context, hub, id string) apMemberInfo {
	s.t.Helper()
	out, err := s.run(ctx, "exec", "-T", hub, "hearth", "cluster", "status", "--json", "--data-dir", hubDataDir)
	if err != nil {
		return apMemberInfo{}
	}
	var st struct {
		Members []apMemberInfo `json:"members"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return apMemberInfo{}
	}
	for _, m := range st.Members {
		if m.ID == id {
			return m
		}
	}
	return apMemberInfo{}
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

// agentStreamHub is the hub the agent streams to: the first of the hubs it
// keeps, which it reorders on each Welcome.
func (s *stack) agentStreamHub(ctx context.Context) string {
	s.t.Helper()
	out, err := s.run(ctx, "exec", "-T", agentName, "head", "-n", "1", agentDataDir+"/hubs")
	if err != nil {
		s.t.Fatalf("read the agent's hubs: %v", err)
	}
	u, err := url.Parse(strings.TrimSpace(out))
	if err != nil {
		s.t.Fatalf("the agent's first hub: %v", err)
	}
	return u.Hostname()
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

// auditIDs returns every audit entry, by id (its HLC), action and time:
// two entries of two hubs may share an HLC.
func (c *apiClient) auditIDs(ctx context.Context) map[string]string {
	c.t.Helper()
	out := map[string]string{}
	path := "/api/v1/audit?limit=500"
	for {
		b, err := c.raw(ctx, path)
		if err != nil {
			c.t.Fatalf("audit: %v", err)
		}
		var page struct {
			Entries []struct {
				ID     int64  `json:"id"`
				Action string `json:"action"`
				Result string `json:"result"`
				TS     string `json:"ts"`
			} `json:"entries"`
			NextCursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			c.t.Fatalf("audit: %v", err)
		}
		for _, e := range page.Entries {
			out[fmt.Sprintf("%d %s %s", e.ID, e.Action, e.TS)] = e.Result
		}
		if page.NextCursor == "" || len(page.Entries) == 0 {
			return out
		}
		path = "/api/v1/audit?limit=500&before=" + url.QueryEscape(page.NextCursor)
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
