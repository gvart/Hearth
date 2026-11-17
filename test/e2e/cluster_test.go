// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// Time bounds of hub failover in a 3-hub cluster (cluster.compose.yaml). Never
// raise one to make CI pass. DeviceVisibleWithin holds for a cluster too.
const (
	// FormationWithin bounds forming the cluster: from starting hub-a until
	// all three hubs are voters with one leader. It covers three container
	// starts, two joins and two promotions, not the image build.
	FormationWithin = 60 * time.Second
	// FailoverWithin bounds how long after the leader is killed (SIGKILL) the
	// agent is connected to the newly elected leader: the election plus the
	// agent's move to the new leader.
	FailoverWithin = 10 * time.Second
	// UnavailableWithin bounds how long after a second hub stops (no quorum
	// left) an API write on the last hub takes to fail with 503
	// cluster_unavailable: the leader stepping down, then up to 5 s waiting
	// for a leader, once for the action and once for its audit entry.
	UnavailableWithin = 15 * time.Second
	// WritesResumeWithin bounds how long after the stopped hub starts again
	// API writes succeed again: its start, an election and the barrier.
	WritesResumeWithin = 15 * time.Second
	// AgentBackWithin bounds how long after the quorum returns the agent is
	// connected to the leader again. While no hub would take it, the agent
	// failed whole rounds of hubs and backed off exponentially, up to the
	// agent's 1 min cap (internal/agent/backoff.go), so it may be waiting out
	// a long delay; then one round plus the leader's takeover.
	AgentBackWithin = time.Minute + FailoverWithin
	// RejoinWithin bounds how long after the killed hub starts again it is a
	// follower serving the cluster's current data through its API.
	RejoinWithin = 20 * time.Second
	// RemoveWithin bounds how long after `hearth cluster remove` starts on a
	// follower every survivor reports one leader and 2 voters: the forward to
	// the leader, the configuration change and its replication.
	RemoveWithin = 10 * time.Second
	// ReplaceWithin bounds joining a replacement hub: from creating its join
	// token until every hub reports one leader and 3 voters again. It covers
	// one container start, a join and a promotion (FormationWithin covers
	// three starts and two of each).
	ReplaceWithin = 30 * time.Second
)

const (
	hubDataDir = "/var/lib/hearth/hub"
	agentName  = "agent"
)

var clusterHubs = []string{"hub-a", "hub-b", "hub-c"}

// replacementHub joins in place of a hub that was removed for good.
const replacementHub = "hub-d"

// TestClusterFailover guards hub high availability (docs/cluster.md): an
// agent enrolled through a follower, the leader killed, writes on followers,
// quorum lost and regained, the killed hub rejoining, and a dead hub removed
// and replaced.
func TestClusterFailover(t *testing.T) {
	ctx := t.Context()
	s := newStack(t, "hearth-e2e-cluster", "cluster.compose.yaml", append(slices.Clone(clusterHubs), replacementHub, agentName))
	s.compose(ctx, "build")

	// 1. hub-a forms the cluster; hub-b and hub-c join it with a token each.
	formAt := time.Now()
	s.compose(ctx, "up", "--detach", "--wait", "--wait-timeout", "60", "hub-a", agentName)
	for _, h := range clusterHubs[1:] {
		tok := s.clusterJoinToken(ctx, "hub-a", formAt.Add(FormationWithin))
		s.composeEnv(ctx, []string{"HEARTH_JOIN_TOKEN=" + tok},
			"up", "--detach", "--no-deps", "--wait", "--wait-timeout", "60", h)
	}
	leader := s.waitLeader(ctx, clusterHubs, formAt.Add(FormationWithin), 3)
	t.Logf("TIMING formation: 3 voters, leader %s, in %v", leader, since(formAt))

	// Log in on every hub up front (a login is a write, forwarded on a
	// follower), so polling starts at once after the failover.
	apis := map[string]*apiClient{}
	for _, h := range clusterHubs {
		apis[h] = s.loginTo(ctx, h)
	}

	// 2. Enroll the agent through a follower: the follower sends it to the
	// leader, and the device is online within the headline bound.
	follower := others(clusterHubs, leader)[0]
	token := apis[follower].createToken(ctx)
	joinAt := time.Now()
	s.compose(ctx, "exec", "-T", agentName, "hearth", "agent", "join", "https://"+follower+":7443", token, "--data-dir", agentDataDir)
	s.startAgent(ctx, agentName)
	dev := apis[follower].waitDevice(ctx, agentName, joinAt.Add(DeviceVisibleWithin), "online", func(d device) bool {
		return d.Status == "online"
	})
	t.Logf("TIMING enroll via follower %s → online in %v", follower, since(joinAt))

	// 3. Kill the leader. A survivor is elected, the agent connects to it
	// within FailoverWithin, and the device never goes offline, even past a
	// full offline timeout under the new leader.
	killed := leader
	killAt := time.Now()
	s.compose(ctx, "kill", "--signal", "SIGKILL", killed)
	killedAt := s.finishedAt(ctx, killed) // the docker host's clock, which stamps last_seen
	survivors := others(clusterHubs, killed)
	leader = s.waitLeader(ctx, survivors, killAt.Add(FailoverWithin), 3)
	electedAt := time.Now()
	t.Logf("TIMING kill %s → %s elected in %v", killed, leader, since(killAt))
	apis[leader].waitDevice(ctx, agentName, killAt.Add(FailoverWithin), "connected to the new leader", func(d device) bool {
		return d.Status == "online" && d.LastSeen.After(killedAt)
	})
	t.Logf("TIMING kill %s → agent connected to %s in %v", killed, leader, since(killAt))

	// 4. Writes on the remaining follower, through the API (a fresh login and
	// a token) and through the CLI on its host, while the watch below runs on.
	follower = others(survivors, leader)[0]
	fapi := s.loginTo(ctx, follower)
	fapi.createToken(ctx)
	s.compose(ctx, "exec", "-T", follower, "hearth", "token", "create", "--data-dir", hubDataDir)
	t.Logf("API login + token and CLI token create on follower %s: ok", follower)

	// Without the agent, the new leader would mark the device offline
	// OfflineAfter (30 s) after its term started, at the next 5 s sweep:
	// OfflineWithin after the election is past that.
	watchUntil := electedAt.Add(OfflineWithin)
	apis[leader].watchDevice(ctx, agentName, watchUntil, func(d device) bool { return d.Status == "online" })
	for _, h := range survivors {
		if logs := s.compose(ctx, "logs", "--no-color", h); strings.Contains(logs, "device.offline") {
			t.Errorf("%s logged a device.offline transition after the failover", h)
		}
	}
	t.Logf("device stayed online on %s for %v after the election", leader, OfflineWithin)

	// 5. Stop the follower: the leader alone has no quorum, and a write on it
	// fails with 503 cluster_unavailable. Then start it again: writes work.
	stopAt := time.Now()
	s.compose(ctx, "stop", "--timeout", "5", follower)
	last := apis[leader]
	last.http.Timeout = 2 * UnavailableWithin // a no-quorum write waits, by design
	status, code, err := last.postStatus(ctx, "/api/v1/tokens", map[string]string{"ttl": "5m"})
	if err != nil || status != http.StatusServiceUnavailable || code != "cluster_unavailable" {
		t.Fatalf("write without quorum on %s: got %d %q (err %v), want 503 cluster_unavailable", leader, status, code, err)
	}
	if took := time.Since(stopAt); took > UnavailableWithin {
		t.Fatalf("write without quorum on %s failed after %v, want within %v", leader, took, UnavailableWithin)
	}
	t.Logf("TIMING stop %s → write on %s answered 503 cluster_unavailable in %v", follower, leader, since(stopAt))

	startAt := time.Now()
	s.compose(ctx, "start", follower)
	quorumAt := s.startedAt(ctx, follower) // the docker host's clock
	waitFor(ctx, t, startAt.Add(WritesResumeWithin), "writes on "+leader+" to work again", func() (bool, string) {
		status, code, err := last.postStatus(ctx, "/api/v1/tokens", map[string]string{"ttl": "5m"})
		if err != nil {
			return false, err.Error()
		}
		return status == http.StatusCreated || status == http.StatusOK, fmt.Sprintf("%d %s", status, code)
	})
	t.Logf("TIMING start %s → writes work again in %v", follower, since(startAt))

	// 6. Start the killed hub: it rejoins as a follower and its API serves the
	// cluster's data, the device included.
	rejoinAt := time.Now()
	s.compose(ctx, "start", killed)
	leader = s.waitLeader(ctx, clusterHubs, rejoinAt.Add(RejoinWithin), 3)
	if leader == killed {
		t.Fatalf("%s led the cluster right after rejoining; want it to rejoin as a follower", killed)
	}
	want := s.clusterStatus(ctx, leader)
	waitFor(ctx, t, rejoinAt.Add(RejoinWithin), killed+" to catch up", func() (bool, string) {
		st, err := s.status(ctx, killed)
		if err != nil {
			return false, err.Error()
		}
		return st.State == "Follower" && st.AppliedIndex >= want.CommitIndex,
			fmt.Sprintf("state %s, applied %d of %d", st.State, st.AppliedIndex, want.CommitIndex)
	})
	kapi := s.loginTo(ctx, killed) // retries while it answers 503 catching_up
	got := kapi.waitDevice(ctx, agentName, rejoinAt.Add(RejoinWithin), "online on the rejoined hub", func(d device) bool {
		return d.Status == "online"
	})
	if got.ID != dev.ID {
		t.Errorf("device id on the rejoined %s: %s, want %s", killed, got.ID, dev.ID)
	}
	t.Logf("TIMING start %s → follower serving the device in %v", killed, since(rejoinAt))

	// The agent finds its way back to the leader after the quorum loss.
	apis[leader].waitDevice(ctx, agentName, startAt.Add(AgentBackWithin), "connected after the quorum loss", func(d device) bool {
		return d.Status == "online" && d.LastSeen.After(quorumAt)
	})
	t.Logf("TIMING start %s → agent connected to %s again in %v", follower, leader, since(startAt))

	// 7. A hub dies for good: kill the leader, remove it through a follower
	// (forwarded to the new leader), join a replacement in its place, and
	// survive another leader kill with 3 voters again.
	dead := leader
	deadAt := time.Now()
	s.compose(ctx, "kill", "--signal", "SIGKILL", dead)
	survivors = others(clusterHubs, dead)
	leader = s.waitLeader(ctx, survivors, deadAt.Add(FailoverWithin), 3)
	t.Logf("TIMING kill %s → %s elected in %v", dead, leader, since(deadAt))

	via := others(survivors, leader)[0]
	removeAt := time.Now()
	out := s.compose(ctx, "exec", "-T", via, "hearth", "cluster", "remove", dead, "--data-dir", hubDataDir)
	t.Logf("cluster remove %s on %s: %s", dead, via, strings.TrimSpace(out))
	s.waitLeader(ctx, survivors, removeAt.Add(RemoveWithin), 2)
	t.Logf("TIMING remove %s on follower %s → 2 voters in %v", dead, via, since(removeAt))

	replaceAt := time.Now()
	tok := s.clusterJoinToken(ctx, via, replaceAt.Add(ReplaceWithin))
	s.composeEnv(ctx, []string{"HEARTH_JOIN_TOKEN=" + tok, "HEARTH_JOIN_URL=https://" + via + ":7443"},
		"up", "--detach", "--no-deps", "--wait", "--wait-timeout", "60", replacementHub)
	current := append(slices.Clone(survivors), replacementHub)
	leader = s.waitLeader(ctx, current, replaceAt.Add(ReplaceWithin), 3)
	t.Logf("TIMING join %s → 3 voters, leader %s, in %v", replacementHub, leader, since(replaceAt))

	killed = leader
	killAt = time.Now()
	s.compose(ctx, "kill", "--signal", "SIGKILL", killed)
	killedAt = s.finishedAt(ctx, killed)
	leader = s.waitLeader(ctx, others(current, killed), killAt.Add(FailoverWithin), 3)
	t.Logf("TIMING kill %s → %s elected in %v", killed, leader, since(killAt))
	lapi := s.loginTo(ctx, leader) // a write: it needs the majority
	lapi.createToken(ctx)
	lapi.waitDevice(ctx, agentName, killAt.Add(FailoverWithin), "connected after the replacement", func(d device) bool {
		return d.Status == "online" && d.LastSeen.After(killedAt)
	})
	t.Logf("TIMING kill → login, token and agent connected to %s in %v", leader, since(killAt))
}

// clusterStatusJSON is the part of `hearth cluster status --json` the test reads.
type clusterStatusJSON struct {
	NodeID       string `json:"node_id"`
	State        string `json:"state"`
	LeaderID     string `json:"leader_id"`
	CommitIndex  uint64 `json:"commit_index"`
	AppliedIndex uint64 `json:"applied_index"`
	Peers        []struct {
		ID       string `json:"id"`
		Suffrage string `json:"suffrage"`
	} `json:"peers"`
}

// status runs `hearth cluster status --json` on the hub's host.
func (s *stack) status(ctx context.Context, hub string) (clusterStatusJSON, error) {
	var st clusterStatusJSON
	out, err := s.run(ctx, "exec", "-T", hub, "hearth", "cluster", "status", "--json", "--data-dir", hubDataDir)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return st, fmt.Errorf("cluster status on %s: %w", hub, err)
	}
	return st, nil
}

func (s *stack) clusterStatus(ctx context.Context, hub string) clusterStatusJSON {
	s.t.Helper()
	st, err := s.status(ctx, hub)
	if err != nil {
		s.t.Fatal(err)
	}
	return st
}

// waitLeader waits until every one of hubs reports the same leader, that
// leader is among hubs and calls itself Leader, and the cluster has voters
// voters. It returns the leader's node ID, which is its service name.
func (s *stack) waitLeader(ctx context.Context, hubs []string, deadline time.Time, voters int) string {
	s.t.Helper()
	var leader string
	waitFor(ctx, s.t, deadline, "one leader among "+strings.Join(hubs, ", "), func() (bool, string) {
		leader = ""
		for _, h := range hubs {
			st, err := s.status(ctx, h)
			switch {
			case err != nil:
				return false, err.Error()
			case st.LeaderID == "" || !slices.Contains(hubs, st.LeaderID):
				return false, fmt.Sprintf("%s: leader %q", h, st.LeaderID)
			case leader != "" && st.LeaderID != leader:
				return false, fmt.Sprintf("%s: leader %s, another hub says %s", h, st.LeaderID, leader)
			case st.NodeID == st.LeaderID && st.State != "Leader":
				return false, fmt.Sprintf("%s: state %s", h, st.State)
			}
			n := 0
			for _, p := range st.Peers {
				if p.Suffrage == "Voter" {
					n++
				}
			}
			if n != voters {
				return false, fmt.Sprintf("%s: %d voters", h, n)
			}
			leader = st.LeaderID
		}
		return true, ""
	})
	return leader
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

// watchDevice polls the device until, and fails the test as soon as it does
// not satisfy ok or cannot be read before until.
func (c *apiClient) watchDevice(ctx context.Context, hostname string, until time.Time, ok func(device) bool) {
	c.t.Helper()
	for time.Now().Before(until) {
		devs, err := c.devices(ctx)
		if err != nil {
			c.t.Fatalf("watch %s: %v", hostname, err)
		}
		i := slices.IndexFunc(devs, func(d device) bool { return d.Hostname == hostname })
		if i < 0 {
			c.t.Fatalf("watch %s: not listed", hostname)
		}
		if d := devs[i]; !ok(d) {
			c.t.Fatalf("watch %s: status %s, last_seen %s", hostname, d.Status, d.LastSeen.Format(time.RFC3339Nano))
		}
		if err := sleep(ctx, 200*time.Millisecond); err != nil {
			c.t.Fatal(err)
		}
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

func others(hubs []string, not string) []string {
	return slices.DeleteFunc(slices.Clone(hubs), func(h string) bool { return h == not })
}

func since(t time.Time) time.Duration { return time.Since(t).Round(time.Millisecond) }
