// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/pki"
)

// cluster is the leadership view every fake hub shares: one leader URL and
// every hub URL, as Raft would report them.
type cluster struct {
	mu     sync.Mutex
	leader string
	urls   []string
}

func (c *cluster) setLeader(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leader = url
}

// member is one hub's hub.Leadership over the shared cluster view.
type member struct {
	c   *cluster
	url string
}

func (m *member) IsLeader() bool {
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	return m.c.leader == m.url
}

func (m *member) LeaderAgentURL() string {
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	return m.c.leader
}

func (m *member) AgentURLs() []string {
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	return append([]string(nil), m.c.urls...)
}

// startCluster starts hubs A and B sharing a CA and store, with A the leader.
func startCluster(t *testing.T) (c *cluster, a, b *restartableHub) {
	t.Helper()
	c = &cluster{}
	ma, mb := &member{c: c}, &member{c: c}
	a = startClusterHub(t, time.Second, nil, ma)
	b = startClusterHub(t, time.Second, a, mb)
	ma.url, mb.url = a.url, b.url
	c.urls = []string{a.url, b.url}
	c.setLeader(a.url)
	return c, a, b
}

func connectedTo(h *restartableHub, id string, n int) func() bool {
	return func() bool { return strings.Count(h.logs.String(), `msg="agent connected" device_id=`+id) >= n }
}

func readHubsFile(t *testing.T, dataDir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dataDir, agent.HubsFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRunFailsOverToAnotherHub: the agent learns hub B from A's Welcome and,
// when A dies and B takes over, reconnects to B.
func TestRunFailsOverToAnotherHub(t *testing.T) {
	c, a, b := startCluster(t)
	id, dataDir := a.join(t)
	ag := startAgent(t, dataDir)
	waitFor(t, 10*time.Second, "connection to A", connectedTo(a, id, 1))
	waitFor(t, 5*time.Second, "the hub list to be saved", func() bool {
		raw, err := os.ReadFile(filepath.Join(dataDir, agent.HubsFile))
		return err == nil && string(raw) == a.url+"\n"+b.url+"\n"
	})
	waitFor(t, 5*time.Second, "a heartbeat", func() bool { return strings.Contains(a.logs.String(), `msg=heartbeat device_id=`+id) })

	died := time.Now()
	a.stop()
	c.setLeader(b.url)
	waitFor(t, 5*time.Second, "failover to B", connectedTo(b, id, 1))
	t.Logf("failed over %v after A died", time.Since(died).Round(time.Millisecond))
	if took := time.Since(died); took > 2*time.Second {
		t.Errorf("failover took %v, want under 2s", took)
	}
	ag.assertRunning(t)
}

// TestRunFollowerRedirectsToLeader: a follower's refusal sends the agent
// straight to the leader it names, without a backoff.
func TestRunFollowerRedirectsToLeader(t *testing.T) {
	c, a, b := startCluster(t)
	id, dataDir := a.join(t) // the agent knows only A
	c.setLeader(b.url)

	started := time.Now()
	ag := startAgent(t, dataDir)
	waitFor(t, 5*time.Second, "redirect to B", connectedTo(b, id, 1))
	if took := time.Since(started); took > time.Second {
		t.Errorf("redirect took %v, want under 1s", took)
	}
	if !strings.Contains(a.logs.String(), `msg="agent refused: not the leader" device_id=`+id) {
		t.Errorf("A did not refuse the agent:\n%s", a.logs.String())
	}
	if strings.Contains(a.logs.String(), `msg="agent connected"`) {
		t.Error("follower A accepted the agent")
	}
	if strings.Contains(ag.logs.String(), "reconnecting") {
		t.Errorf("agent backed off instead of following the redirect:\n%s", ag.logs.String())
	}
	// B's Welcome put B first.
	waitFor(t, 5*time.Second, "the hub list to be saved", func() bool {
		raw, err := os.ReadFile(filepath.Join(dataDir, agent.HubsFile))
		return err == nil && string(raw) == b.url+"\n"+a.url+"\n"
	})
}

// TestRunHubsPersistAcrossRestarts: hubs learned in one run are used by the
// next, even when the join URL is dead.
func TestRunHubsPersistAcrossRestarts(t *testing.T) {
	c, a, b := startCluster(t)
	id, dataDir := a.join(t)
	ag := startAgent(t, dataDir)
	waitFor(t, 10*time.Second, "connection to A", connectedTo(a, id, 1))
	waitFor(t, 5*time.Second, "the hub list to be saved", func() bool {
		_, err := os.Stat(filepath.Join(dataDir, agent.HubsFile))
		return err == nil
	})
	ag.stop(t)

	if fi, err := os.Stat(filepath.Join(dataDir, agent.HubsFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s: mode %v err %v, want 0600", agent.HubsFile, fi.Mode().Perm(), err)
	}
	if got, want := readHubsFile(t, dataDir), a.url+"\n"+b.url+"\n"; got != want {
		t.Errorf("%s = %q, want %q", agent.HubsFile, got, want)
	}
	if raw, err := os.ReadFile(filepath.Join(dataDir, agent.HubURLFile)); err != nil || string(raw) != a.url+"\n" {
		t.Errorf("%s = %q (err %v), want the join URL kept", agent.HubURLFile, raw, err)
	}

	a.stop()
	c.setLeader(b.url)
	startAgent(t, dataDir)
	waitFor(t, 5*time.Second, "connection to B after restart", connectedTo(b, id, 1))
}

// TestRunAllHubsDownBacksOff: with every hub down, each round tries every hub
// once and then waits, so attempts stay few.
func TestRunAllHubsDownBacksOff(t *testing.T) {
	_, a, b := startCluster(t)
	_, dataDir := a.join(t)
	if err := os.WriteFile(filepath.Join(dataDir, agent.HubsFile), []byte(a.url+"\n"+b.url+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.stop()
	b.stop()

	ag := startAgent(t, dataDir)
	time.Sleep(3 * time.Second)
	ag.assertRunning(t)
	ag.stop(t)
	logs := ag.logs.String()
	// Rounds start at 0, then after 0.5–1 s and 1–2 s more: 2 or 3 rounds of
	// 2 attempts in 3 s. A hot loop would make hundreds.
	attempts := strings.Count(logs, "trying the next hub") + strings.Count(logs, "reconnecting")
	if attempts < 4 || attempts > 6 {
		t.Errorf("%d attempts in 3s with both hubs down, want 4-6:\n%s", attempts, logs)
	}
	for _, h := range []*restartableHub{a, b} {
		if !strings.Contains(logs, "hub="+strings.TrimPrefix(h.url, "https://")) {
			t.Errorf("agent never tried %s:\n%s", h.url, logs)
		}
	}
}

// TestJoinFollowerRedirectsToLeader: join through a follower enrolls with the
// leader it names and saves the hubs; hub_url stays the URL given.
func TestJoinFollowerRedirectsToLeader(t *testing.T) {
	c, a, b := startCluster(t)
	c.setLeader(b.url)
	tok, err := pki.NewToken(a.ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.st.Tokens().Create(t.Context(), tok.Secret, nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(t.TempDir(), "agent")
	id, err := agent.Join(t.Context(), a.url, tok.Encode(), dataDir, "pi")
	if err != nil {
		t.Fatalf("Join via follower: %v", err)
	}
	if !strings.Contains(b.logs.String(), `msg="device enrolled" device_id=`+id) {
		t.Errorf("leader B did not enroll the device:\n%s", b.logs.String())
	}
	if got, want := readHubsFile(t, dataDir), b.url+"\n"+a.url+"\n"; got != want {
		t.Errorf("%s = %q, want %q", agent.HubsFile, got, want)
	}
	if raw, err := os.ReadFile(filepath.Join(dataDir, agent.HubURLFile)); err != nil || string(raw) != a.url+"\n" {
		t.Errorf("%s = %q (err %v), want the URL given to join", agent.HubURLFile, raw, err)
	}
}
