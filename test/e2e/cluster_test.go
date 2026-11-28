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

const (
	hubDataDir = "/var/lib/hearth/hub"
	agentName  = "agent"
)

// Time bounds of the cluster test (cluster.compose.yaml). Never raise one to
// make CI pass.
const (
	// FormationWithin bounds forming the cluster: three container
	// starts and two joins, until every hub sees 3 live storage members.
	FormationWithin = 60 * time.Second
	// WritesWithin bounds how long after a hub is killed a critical write
	// (an enrollment token: the token row and its audit entry) works on the
	// survivors: none at all should be needed, a replica that does not
	// answer is replaced by a stand-in at once.
	WritesWithin = 5 * time.Second
	// ConvergeWithin bounds how long after a partition heals every hub
	// answers the same queries byte for byte: failure detection, hints and
	// an anti-entropy round (every 30 s).
	ConvergeWithin = 60 * time.Second
)

var clusterHubs = []string{"hub-a", "hub-b", "hub-c"}

// TestCluster guards the cluster (N=2, every hub
// master and storage): a hub killed loses no acknowledged critical write and
// the devices stay listed; a partition healed converges to byte-identical
// query results on every hub.
func TestCluster(t *testing.T) {
	ctx := t.Context()
	s := newStack(t, "hearth-e2e-cluster", "cluster.compose.yaml", append(clusterHubs[:3:3], "hub-d", agentName))
	s.compose(ctx, "build")

	// 1. hub-a forms the cluster alone; hub-b and hub-c join it.
	formAt := time.Now()
	s.compose(ctx, "up", "--detach", "--wait", "--wait-timeout", "60", "hub-a", agentName)
	for _, h := range clusterHubs[1:] {
		tok := s.clusterJoinToken(ctx, "hub-a", formAt.Add(FormationWithin))
		s.composeEnv(ctx, []string{"HEARTH_JOIN_TOKEN=" + tok},
			"up", "--detach", "--no-deps", "--wait", "--wait-timeout", "60", h)
	}
	s.waitMembers(ctx, clusterHubs, clusterHubs, formAt.Add(FormationWithin))
	t.Logf("TIMING formation: 3 storage members, N=2, in %v", since(formAt))

	apis := map[string]*apiClient{}
	for _, h := range clusterHubs {
		apis[h] = s.loginTo(ctx, h)
	}

	// 2. Enroll the agent: token from hub-b, join through hub-c. The token
	// names hub-b, its owner, and the agent enrolls there. Every hub lists
	// it online within the headline bound.
	token := apis["hub-b"].createToken(ctx)
	if !strings.HasPrefix(token, "hearth2.") {
		t.Fatalf("token from a master is not a hearth2 token naming its owner")
	}
	joinAt := time.Now()
	s.compose(ctx, "exec", "-T", agentName, "hearth", "agent", "join", "https://hub-c:7443", token, "--data-dir", agentDataDir)
	s.startAgent(ctx, agentName)
	for _, h := range clusterHubs {
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
		return movedTo != streamHub && slices.Contains(clusterHubs, movedTo), "on " + movedTo
	})
	apis[movedTo].waitDevice(ctx, agentName, killAt.Add(DeviceVisibleWithin), "online on "+movedTo, func(d device) bool {
		return d.Status == "online" && d.LastSeen.After(killedAt)
	})
	t.Logf("TIMING kill %s (the agent's stream) → agent on %s and online in %v", streamHub, movedTo, since(killAt))
	s.compose(ctx, "start", streamHub)
	s.waitMembers(ctx, clusterHubs, clusterHubs, time.Now().Add(FormationWithin))
	apis[streamHub] = s.loginTo(ctx, streamHub)

	// 3. Critical writes on every hub, then kill hub-c. Every acknowledged
	// audit entry is still on the survivors, the device is still listed,
	// and critical writes go on.
	for i := range 9 {
		apis[clusterHubs[i%3]].createToken(ctx)
	}
	acked := apis["hub-a"].auditIDs(ctx)
	killAt = time.Now()
	s.compose(ctx, "kill", "--signal", "SIGKILL", "hub-c")
	survivors := clusterHubs[:2]
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
		waitFor(ctx, t, killAt.Add(WritesWithin), "a critical write on "+h, func() (bool, string) {
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
	s.waitMembers(ctx, clusterHubs, clusterHubs, time.Now().Add(FormationWithin))
	apis["hub-c"] = s.loginTo(ctx, "hub-c")
	s.compose(ctx, "exec", "-T", agentName, "pkill", "-f", "hearth agent run")

	s.network(ctx, "disconnect", "hub-a")
	splitAt := time.Now()
	s.waitMembers(ctx, []string{"hub-b", "hub-c"}, []string{"hub-b", "hub-c"}, splitAt.Add(30*time.Second))
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
	waitFor(ctx, t, healAt.Add(ConvergeWithin), "byte-identical answers on every hub", func() (bool, string) {
		for _, path := range []string{"/api/v1/devices", "/api/v1/audit?limit=500"} {
			var first []byte
			for _, h := range clusterHubs {
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
	all := append(clusterHubs[:3:3], "hub-d")
	tok := s.clusterJoinToken(ctx, "hub-a", time.Now().Add(FormationWithin))
	s.composeEnv(ctx, []string{"HEARTH_JOIN_TOKEN=" + tok}, "up", "--detach", "--no-deps", "--wait", "--wait-timeout", "60", "hub-d")
	s.waitMembers(ctx, all, all, time.Now().Add(FormationWithin))
	demoteAt := time.Now()
	s.compose(ctx, "exec", "-T", "hub-a", "hearth", "cluster", "demote", "hub-d", "storage", "--data-dir", hubDataDir)
	waitFor(ctx, t, demoteAt.Add(ConvergeWithin), "hub-d drained and out of storage", func() (bool, string) {
		m := s.memberOf(ctx, "hub-a", "hub-d")
		return !slices.Contains(m.Roles, "storage") && !m.Draining, fmt.Sprintf("%+v", m)
	})
	t.Logf("TIMING demote hub-d from storage → drained in %v", since(demoteAt))
	promoteAt := time.Now()
	if status, code, err := apis["hub-b"].postStatus(ctx, "/api/v1/cluster/members/hub-d/promote",
		map[string]string{"role": "storage"}); err != nil || status != http.StatusOK {
		t.Fatalf("promote hub-d to storage: %d %s %v", status, code, err)
	}
	waitFor(ctx, t, promoteAt.Add(ConvergeWithin), "hub-d in sync", func() (bool, string) {
		m := s.memberOf(ctx, "hub-a", "hub-d")
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
	// Kills, a partition, a heal, a demotion and a promotion are no
	// tampering: the audit log still verifies (#387).
	if b, err := apis["hub-a"].raw(ctx, "/api/v1/audit/verify"); err != nil || !bytes.Contains(b, []byte(`"ok":true`)) {
		t.Errorf("audit verify on hub-a = %s, %v; want ok", b, err)
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

// memberInfo is a member as `hearth cluster status --json` shows it.
type memberInfo struct {
	ID       string   `json:"id"`
	State    string   `json:"state"`
	Roles    []string `json:"roles"`
	Syncing  bool     `json:"syncing"`
	Draining bool     `json:"draining"`
	Progress int      `json:"progress"`
}

// memberOf is member id as hub sees it.
func (s *stack) memberOf(ctx context.Context, hub, id string) memberInfo {
	s.t.Helper()
	out, err := s.run(ctx, "exec", "-T", hub, "hearth", "cluster", "status", "--json", "--data-dir", hubDataDir)
	if err != nil {
		return memberInfo{}
	}
	var st struct {
		Members []memberInfo `json:"members"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return memberInfo{}
	}
	for _, m := range st.Members {
		if m.ID == id {
			return m
		}
	}
	return memberInfo{}
}

// waitMembers waits until every one of hubs sees each of alive as a live
// member, and says it is highly available.
func (s *stack) waitMembers(ctx context.Context, hubs, alive []string, deadline time.Time) {
	s.t.Helper()
	waitFor(ctx, s.t, deadline, strings.Join(alive, ", ")+" alive on "+strings.Join(hubs, ", "), func() (bool, string) {
		for _, h := range hubs {
			out, err := s.run(ctx, "exec", "-T", h, "hearth", "cluster", "status", "--json", "--data-dir", hubDataDir)
			if err != nil {
				return false, err.Error()
			}
			var st struct {
				HighlyAvailable bool `json:"highly_available"`
				Members         []struct {
					ID    string `json:"id"`
					State string `json:"state"`
				} `json:"members"`
			}
			if err := json.Unmarshal([]byte(out), &st); err != nil {
				return false, err.Error()
			}
			if !st.HighlyAvailable {
				return false, h + ": not highly available"
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

// clusterJoinToken creates a cluster join token on the hub's host, retrying
// until the hub's control socket answers.
func (s *stack) clusterJoinToken(ctx context.Context, hub string, deadline time.Time) string {
	s.t.Helper()
	var tok string
	waitFor(ctx, s.t, deadline, "a join token from "+hub, func() (bool, string) {
		out, err := s.run(ctx, "exec", "-T", hub, "hearth", "cluster", "token", "create", "--data-dir", hubDataDir)
		if err != nil {
			return false, err.Error()
		}
		for _, f := range strings.Fields(out) {
			if strings.HasPrefix(f, "hearthj1.") {
				tok = f
				return true, ""
			}
		}
		return false, "no token in the output"
	})
	return tok
}

func (s *stack) composeEnv(ctx context.Context, env []string, args ...string) {
	s.t.Helper()
	if _, err := s.runEnv(ctx, env, args...); err != nil {
		s.t.Fatal(err)
	}
}

// waitFor polls cond until it holds, and fails the test with the last reason
// it gave if that has not happened by deadline.
func waitFor(ctx context.Context, t *testing.T, deadline time.Time, what string, cond func() (bool, string)) {
	t.Helper()
	for {
		ok, why := cond()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %s", what, why)
		}
		if err := sleep(ctx, 200*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
}

func since(t time.Time) time.Duration { return time.Since(t).Round(time.Millisecond) }

// finishedAt is when the service's container last exited, by the docker
// host's clock.
func (s *stack) finishedAt(ctx context.Context, service string) time.Time {
	s.t.Helper()
	return s.containerTime(ctx, service, "{{.State.FinishedAt}}")
}

// postStatus posts body and returns the HTTP status and the API error code.
func (c *apiClient) postStatus(ctx context.Context, path string, body any) (int, string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var e struct {
		Code string `json:"code"`
	}
	if resp.StatusCode/100 != 2 {
		_ = json.NewDecoder(resp.Body).Decode(&e)
	}
	return resp.StatusCode, e.Code, nil
}
