// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// uploadLamp builds the go-lamp example and uploads it to h for platform
// goos/goarch, as `hearth plugin upload` does.
func uploadLamp(t *testing.T, h *restartableHub, goos, goarch string) hub.DevicePluginUpload {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "lamp")
	build := exec.Command("go", "build", "-o", bin, "../../examples/plugins/go-lamp")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	prog, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := os.ReadFile(filepath.Join("..", "..", "examples", "plugins", "go-lamp", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := plugins.ParseManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	sum, size, err := h.blobs.Save(bytes.NewReader(prog))
	if err != nil {
		t.Fatal(err)
	}
	u := hub.DevicePluginUpload{Manifest: m, OS: goos, Arch: goarch, SHA256: sum, Size: size}
	if err := u.Save(t.Context(), h.st, "", "admin/test", time.Now()); err != nil {
		t.Fatal(err)
	}
	return u
}

func setCeiling(t *testing.T, h *restartableHub, id string, c *agentv1.Ceiling) {
	t.Helper()
	b, err := protojson.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.DeviceCeilings().Set(t.Context(), id, b, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
}

func lampGrant(class policy.Class, u hub.DevicePluginUpload) *agentv1.Ceiling {
	return &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{{Name: "go-lamp", MaxClass: string(class), Digest: u.Release().Digest()}}}
}

// TestPluginOnDevice runs the go-lamp example plugin on an agent, end to
// end and in process: uploaded to the hub, allowed by the ceiling the hub
// sets, pushed to the agent, fetched with its client certificate, checked,
// and run through policy, audited.
func TestPluginOnDevice(t *testing.T) {
	h := startRestartableHub(t, 100*time.Millisecond)
	id, dataDir := h.join(t)
	u := uploadLamp(t, h, runtime.GOOS, runtime.GOARCH)
	setCeiling(t, h, id, lampGrant(policy.Safe, u))
	startAgentWith(t, agent.Config{DataDir: dataDir, FactsInterval: time.Hour})
	pol := policy.New(h.st.Audit())
	runner := hub.DevicePluginRunner{Agents: h.agents, Store: h.st, Policy: pol}
	waitFor(t, 20*time.Second, "the plugin installed", func() bool {
		d, err := runner.Device(t.Context(), id)
		return err == nil && len(d.Plugins) == 1 && d.Plugins[0].Installed
	})
	d, err := runner.Device(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Supported || d.OS != runtime.GOOS || d.Arch != runtime.GOARCH || d.Plugins[0].SHA256 != u.SHA256 ||
		len(d.Plugins[0].Commands) != 2 || !d.Plugins[0].Commands[0].Allowed {
		t.Fatalf("device plugins = %+v", d)
	}
	prog := filepath.Join(dataDir, agent.PluginsDir, "go-lamp", u.SHA256)
	if fi, err := os.Stat(prog); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("installed program: %v, %v", fi, err)
	}

	res, err := runner.Run(t.Context(), policy.ActorWeb, "10.0.0.1", id, "go-lamp",
		plugins.CommandRequest{Command: "turn_on", Device: "lamp"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "lamp is on" {
		t.Errorf("output = %q", res.Output)
	}
	entries, err := h.st.Audit().List(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(entries, func(e store.AuditEntry) bool {
		return e.Action == string(policy.DevicePluginCommandSafe) && e.Target == id && e.Decision == policy.Allow
	}) {
		t.Errorf("no allowed %s in the audit log: %+v", policy.DevicePluginCommandSafe, entries)
	}

	// Undeclared: denied on the hub, audited, never sent.
	if _, err := runner.Run(t.Context(), policy.ActorWeb, "10.0.0.1", id, "go-lamp",
		plugins.CommandRequest{Command: "self_destruct"}); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("undeclared command: %v, want denied", err)
	}

	// The agent refuses a class above its ceiling even when the hub claims
	// a lower one: it reads the class from the manifest it installed.
	setCeiling(t, h, id, lampGrant(policy.Read, u))
	waitFor(t, 10*time.Second, "the ceiling lowered", func() bool {
		f := reported(t, h, id)
		return f.Ceiling != nil && len(f.Ceiling.Plugins) == 1 && f.Ceiling.Plugins[0].Class == policy.Read
	})
	if _, err := runner.Run(t.Context(), policy.ActorWeb, "10.0.0.1", id, "go-lamp",
		plugins.CommandRequest{Command: "turn_on"}); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Errorf("safe command under a read ceiling: %v, want beyond the ceiling", err)
	}
	r, err := h.agents.Plugin(t.Context(), id, u.Release().Digest(), policy.Read,
		&agentv1.PluginCommand{Plugin: "go-lamp", Sha256: u.SHA256, Command: "turn_on"}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r.GetOk() || !r.GetDenied() {
		t.Errorf("agent ran a safe command under a read ceiling: %v", r)
	}

	// Taken off the ceiling, the plugin is removed from the device.
	setCeiling(t, h, id, &agentv1.Ceiling{})
	waitFor(t, 10*time.Second, "the plugin removed", func() bool {
		_, err := os.Stat(filepath.Join(dataDir, agent.PluginsDir, "go-lamp"))
		st, serr := h.agents.PluginStatus(t.Context(), id)
		return os.IsNotExist(err) && serr == nil && len(st.GetPlugins()) == 0
	})
	if _, err := runner.Run(t.Context(), policy.ActorWeb, "10.0.0.1", id, "go-lamp",
		plugins.CommandRequest{Command: "turn_on"}); !errors.Is(err, hub.ErrPluginNotInstalled) {
		t.Errorf("removed plugin: %v, want not installed", err)
	}
}

// TestPluginOnDeviceRefused: the agent installs nothing for another
// platform, nor what its --local-ceiling does not allow, whatever the hub
// sets.
func TestPluginOnDeviceRefused(t *testing.T) {
	t.Run("another platform", func(t *testing.T) {
		h := startRestartableHub(t, 100*time.Millisecond)
		id, dataDir := h.join(t)
		u := uploadLamp(t, h, "plan9", runtime.GOARCH)
		setCeiling(t, h, id, lampGrant(policy.Safe, u))
		startAgentWith(t, agent.Config{DataDir: dataDir, FactsInterval: time.Hour})
		runner := hub.DevicePluginRunner{Agents: h.agents, Store: h.st, Policy: policy.New(h.st.Audit())}
		waitFor(t, 20*time.Second, "the agent's report", func() bool {
			d, err := runner.Device(t.Context(), id)
			return err == nil && len(d.Plugins) == 1 && d.Plugins[0].Error != "" && d.Connected
		})
		d, _ := runner.Device(t.Context(), id)
		if d.Plugins[0].Installed {
			t.Fatalf("installed a program of another platform: %+v", d.Plugins[0])
		}
		if _, err := os.Stat(filepath.Join(dataDir, agent.PluginsDir, "go-lamp")); !os.IsNotExist(err) {
			t.Errorf("program on disk: %v", err)
		}
	})
	t.Run("local ceiling", func(t *testing.T) {
		h := startRestartableHub(t, 100*time.Millisecond)
		id, dataDir := h.join(t)
		u := uploadLamp(t, h, runtime.GOOS, runtime.GOARCH)
		setCeiling(t, h, id, lampGrant(policy.Dangerous, u))
		startAgentWith(t, agent.Config{DataDir: dataDir, LocalCeiling: true, FactsInterval: time.Hour})
		waitFor(t, 10*time.Second, "the locked agent's facts", func() bool { return reported(t, h, id).CeilingLocked })
		time.Sleep(500 * time.Millisecond) // a few heartbeats, each pushing the plugins
		if _, err := os.Stat(filepath.Join(dataDir, agent.PluginsDir, "go-lamp")); !os.IsNotExist(err) {
			t.Errorf("locked agent installed the hub's plugin: %v", err)
		}
		// Even sent straight to the agent, past the hub's own check.
		if _, err := h.agents.Plugin(t.Context(), id, u.Release().Digest(), policy.Read,
			&agentv1.PluginCommand{Plugin: "go-lamp", Sha256: u.SHA256, Command: "turn_on"}, 10*time.Second); !errors.Is(err, policy.ErrBeyondCeiling) {
			t.Errorf("hub sent a command beyond the reported ceiling: %v", err)
		}
	})
	t.Run("local flag allows it", func(t *testing.T) {
		h := startRestartableHub(t, 100*time.Millisecond)
		id, dataDir := h.join(t)
		uploadLamp(t, h, runtime.GOOS, runtime.GOARCH)
		startAgentWith(t, agent.Config{
			DataDir: dataDir, LocalCeiling: true, FactsInterval: time.Hour,
			Ceiling: agent.Ceiling{Plugins: []agent.PluginGrant{{Name: "go-lamp", Class: policy.Safe}}},
		})
		runner := hub.DevicePluginRunner{Agents: h.agents, Store: h.st, Policy: policy.New(h.st.Audit())}
		waitFor(t, 20*time.Second, "the plugin installed", func() bool {
			d, err := runner.Device(t.Context(), id)
			return err == nil && len(d.Plugins) == 1 && d.Plugins[0].Installed
		})
		res, err := runner.Run(t.Context(), policy.ActorWeb, "10.0.0.1", id, "go-lamp", plugins.CommandRequest{Command: "turn_off"})
		if err != nil || res.Output == "" {
			t.Fatalf("turn_off: %q, %v", res.Output, err)
		}
	})
}

// TestPluginNewReleaseNeedsApproval: a new release uploaded under the name
// of one a device runs is not installed until its grant is moved to it; the
// device keeps running the release it was allowed.
func TestPluginNewReleaseNeedsApproval(t *testing.T) {
	h := startRestartableHub(t, 100*time.Millisecond)
	id, dataDir := h.join(t)
	v1 := uploadLamp(t, h, runtime.GOOS, runtime.GOARCH)
	setCeiling(t, h, id, lampGrant(policy.Safe, v1))
	startAgentWith(t, agent.Config{DataDir: dataDir, FactsInterval: time.Hour})
	runner := hub.DevicePluginRunner{Agents: h.agents, Store: h.st, Policy: policy.New(h.st.Audit())}
	installed := func(version string, wantErr bool) func() bool {
		return func() bool {
			d, err := runner.Device(t.Context(), id)
			return err == nil && len(d.Plugins) == 1 && d.Plugins[0].Installed &&
				d.Plugins[0].Version == version && (d.Plugins[0].Error != "") == wantErr
		}
	}
	waitFor(t, 20*time.Second, "v1 installed", installed(v1.Manifest.Version, false))

	// The same program, relabelled: every command now "read".
	v2 := v1
	v2.Manifest.Version = "9.9.9"
	v2.Manifest.Commands = slices.Clone(v1.Manifest.Commands)
	for i := range v2.Manifest.Commands {
		v2.Manifest.Commands[i].Class = policy.Read
	}
	if err := v2.Save(t.Context(), h.st, "", "admin/test", time.Now()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "v2 refused, v1 kept", installed(v1.Manifest.Version, true))
	// Commands still run v1, at v1's classes.
	if _, err := runner.Run(t.Context(), policy.ActorWeb, "10.0.0.1", id, "go-lamp", plugins.CommandRequest{Command: "turn_on"}); err != nil {
		t.Fatal(err)
	}
	setCeiling(t, h, id, lampGrant(policy.Read, v1))
	waitFor(t, 10*time.Second, "the ceiling lowered", func() bool {
		f := reported(t, h, id)
		return f.Ceiling != nil && len(f.Ceiling.Plugins) == 1 && f.Ceiling.Plugins[0].Class == policy.Read
	})
	if _, err := runner.Run(t.Context(), policy.ActorWeb, "10.0.0.1", id, "go-lamp",
		plugins.CommandRequest{Command: "turn_on"}); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Fatalf("the relabelled manifest's class was taken: %v", err)
	}

	// Approved: v2 replaces v1.
	setCeiling(t, h, id, lampGrant(policy.Read, v2))
	waitFor(t, 10*time.Second, "v2 installed", installed(v2.Manifest.Version, false))
}
