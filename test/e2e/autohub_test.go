// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// Time bounds of the auto-hub test (autohub.compose.yaml). Never raise one
// to make CI pass.
const (
	// AutoHubWithin bounds how long after its install command a capable
	// device is a live member of the cluster: install, enrollment, the
	// hub's join and its first sync.
	AutoHubWithin = 60 * time.Second
	// CopiesWithin bounds how long until the devices that became storage
	// members have copied their rows (no longer syncing).
	CopiesWithin = 90 * time.Second
)

var autoDevices = []string{"dev-1", "dev-2", "dev-3"}

// TestAutoHubs guards #328: on a bare hub (a laptop), the Add device
// command pasted on capable devices makes them hubs, the first two masters
// and the third storage only (3 masters at most); once they hold copies the
// first hub can be killed, and the devices carry on: the UI and Add device
// work on another master and every agent is online there.
func TestAutoHubs(t *testing.T) {
	ctx := t.Context()
	s := newStack(t, "hearth-e2e-autohub", "autohub.compose.yaml", append([]string{"hub-a", "releases"}, autoDevices...))
	s.compose(ctx, "build")
	s.compose(ctx, "up", "--detach", "--wait", "--wait-timeout", "60", "hub-a", "releases", "dev-1", "dev-2", "dev-3")
	a := s.loginTo(ctx, "hub-a")

	// 1. dev-1 and dev-2: the Add device dialog's command, as pasted. Each
	// becomes a hub: storage and master, with the CA key.
	ids := map[string]string{}
	for _, d := range autoDevices[:2] {
		at := time.Now()
		s.installAutoHub(ctx, a, d)
		ids[d] = s.waitNodeOf(ctx, d, at.Add(AutoHubWithin))
		s.waitLive(ctx, "hub-a", ids[d], at.Add(AutoHubWithin))
		t.Logf("TIMING %s: install command → live member %s in %v", d, ids[d], since(at))
	}
	for _, d := range autoDevices[:2] {
		if m := s.memberOf(ctx, "hub-a", ids[d]); !slices.Contains(m.Roles, "master") || !slices.Contains(m.Roles, "storage") {
			t.Fatalf("%s roles = %v, want storage and master", d, m.Roles)
		}
		if _, err := s.run(ctx, "exec", "-T", d, "test", "-f", hubDataDir+"/ca.key"); err != nil {
			t.Fatalf("%s holds no CA key, though a master", d)
		}
	}

	// 2. dev-3: 3 masters counted already, so storage only, no CA key.
	at := time.Now()
	s.installAutoHub(ctx, a, "dev-3")
	ids["dev-3"] = s.waitNodeOf(ctx, "dev-3", at.Add(AutoHubWithin))
	s.waitLive(ctx, "hub-a", ids["dev-3"], at.Add(AutoHubWithin))
	if m := s.memberOf(ctx, "hub-a", ids["dev-3"]); slices.Contains(m.Roles, "master") || !slices.Contains(m.Roles, "storage") {
		t.Fatalf("dev-3 roles = %v, want storage only", m.Roles)
	}
	if _, err := s.run(ctx, "exec", "-T", "dev-3", "test", "-e", hubDataDir+"/ca.key"); err == nil {
		t.Fatal("dev-3, storage only, holds the CA key")
	}
	for _, d := range autoDevices {
		if _, err := s.run(ctx, "exec", "-T", d, "test", "-e", hubDataDir+"/join"); err == nil {
			t.Fatalf("%s kept its join file after joining", d)
		}
	}

	// 3. Wait until the devices hold their copies, then kill the laptop.
	waitFor(ctx, t, time.Now().Add(CopiesWithin), "the devices to finish syncing", func() (bool, string) {
		for _, d := range autoDevices {
			if m := s.memberOf(ctx, "dev-1", ids[d]); m.State != "alive" || m.Syncing {
				return false, fmt.Sprintf("%s on dev-1: %+v", d, m)
			}
		}
		return true, ""
	})
	killAt := time.Now()
	s.compose(ctx, "kill", "--signal", "SIGKILL", "hub-a")

	// 4. dev-1 carries on: the UI, a login, Add device, and every agent
	// online there within the headline bound.
	d1 := s.loginTo(ctx, "dev-1")
	if _, err := d1.raw(ctx, "/"); err != nil {
		t.Fatalf("UI on dev-1: %v", err)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := d1.post(ctx, "/api/v1/tokens", map[string]any{"hub": true}, &tok); err != nil || tok.Token == "" {
		t.Fatalf("Add device on dev-1 after hub-a was killed: %v", err)
	}
	for _, d := range autoDevices {
		d1.waitDevice(ctx, d, killAt.Add(DeviceVisibleWithin), "online on dev-1 after hub-a was killed", func(dv device) bool {
			return dv.Status == "online" && dv.LastSeen.After(killAt)
		})
	}
	t.Logf("TIMING kill hub-a → UI, Add device and every agent online on dev-1 in %v", since(killAt))

	// 5. Restart dev-1's hub: it finds dev-2 again without hub-a.
	s.stopProc(ctx, "dev-1", "hearth hub")
	restartAt := time.Now()
	s.startUnit(ctx, "dev-1", "hearth-hub")
	s.waitLive(ctx, "dev-1", ids["dev-2"], restartAt.Add(AutoHubWithin))
	t.Logf("TIMING dev-1 hub restart → dev-2 live again in %v", since(restartAt))
}

// installAutoHub pastes the Add device dialog's install command, with "may
// become a hub" ticked, into device d, then plays systemd: the hub service
// when its condition holds, then the agent.
func (s *stack) installAutoHub(ctx context.Context, c *apiClient, d string) {
	s.t.Helper()
	var tok struct {
		InstallCommand string `json:"install_command"`
	}
	if err := c.post(ctx, "/api/v1/tokens", map[string]any{"hub": true}, &tok); err != nil {
		s.t.Fatalf("Add device with hub: %v", err)
	}
	out, err := s.run(ctx, "exec", "-T", d, "sh", "-c", tok.InstallCommand)
	if err != nil {
		s.t.Fatalf("install on %s: %v\n%s", d, err, out)
	}
	if !strings.Contains(out, "This device becomes a hub") {
		s.t.Fatalf("install on %s did not make it a hub:\n%s", d, out)
	}
	s.startUnit(ctx, d, "hearth-hub")
	s.startUnit(ctx, d, "hearth-agent")
}

// startUnit runs the ExecStart of the systemd unit the installer wrote on d,
// if one of its ConditionPathExists=| paths exists, as systemd would.
func (s *stack) startUnit(ctx context.Context, d, unit string) {
	s.t.Helper()
	script := `u=/etc/systemd/system/` + unit + `.service; ok=1
for p in $(sed -n 's/^ConditionPathExists=|//p' "$u"); do ok=0; [ -e "$p" ] && { ok=1; break; }; done
[ "$ok" = 1 ] || { echo "condition failed"; exit 0; }
exec $(sed -n 's/^ExecStart=//p' "$u") >/proc/1/fd/1 2>&1`
	s.compose(ctx, "exec", "--detach", d, "sh", "-c", script)
}

// stopProc stops the process of d whose command line has pattern.
func (s *stack) stopProc(ctx context.Context, d, pattern string) {
	s.t.Helper()
	s.compose(ctx, "exec", "-T", d, "pkill", "-f", pattern)
	waitFor(ctx, s.t, time.Now().Add(20*time.Second), pattern+" to stop on "+d, func() (bool, string) {
		_, err := s.run(ctx, "exec", "-T", d, "pgrep", "-f", pattern)
		return err != nil, "still running"
	})
}

// waitNodeOf waits for the hub of device d to have its node ID, and returns it.
func (s *stack) waitNodeOf(ctx context.Context, d string, deadline time.Time) string {
	s.t.Helper()
	var id string
	waitFor(ctx, s.t, deadline, "the hub of "+d+" to answer", func() (bool, string) {
		out, err := s.run(ctx, "exec", "-T", d, "hearth", "cluster", "status", "--json", "--data-dir", hubDataDir)
		if err != nil {
			return false, err.Error()
		}
		var st struct {
			NodeID string `json:"node_id"`
		}
		if err := json.Unmarshal([]byte(out), &st); err != nil || st.NodeID == "" {
			return false, out
		}
		id = st.NodeID
		return true, ""
	})
	return id
}

// waitLive waits until hub sees member id alive.
func (s *stack) waitLive(ctx context.Context, hub, id string, deadline time.Time) {
	s.t.Helper()
	waitFor(ctx, s.t, deadline, id+" alive on "+hub, func() (bool, string) {
		m := s.memberOf(ctx, hub, id)
		return m.State == "alive", fmt.Sprintf("%+v", m)
	})
}
