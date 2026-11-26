// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestDeviceCapabilities(t *testing.T) {
	dir, _ := initHub(t)
	st := openStore(t, dir)
	now := time.Now()
	facts := `{"protocol_minor":10,"ceiling":{"exec":[],"restart":[],"logs":["systemd:nginx.service"],"scan":[],"probe":false,"shell":false,"net_edges":false,"docker":false},` +
		`"local_ceiling":{"exec":[],"restart":[],"logs":["systemd:nginx.service"],"scan":[],"probe":false,"shell":false,"net_edges":false,"docker":false}}`
	if err := st.Devices().Upsert(t.Context(), store.Device{ID: "pi", Facts: json.RawMessage(facts), FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}

	out, err := execute(t, "device", "capabilities", "pi", "--data-dir", dir)
	if err != nil {
		t.Fatalf("show: %v\n%s", err, out)
	}
	if !strings.Contains(out, "takes its capabilities from the hub") || !strings.Contains(out, "systemd:nginx.service") {
		t.Errorf("show = %q", out)
	}

	out, err = execute(t, "device", "capabilities", "pi", "--data-dir", dir, "--set", "logs=on", "--set", "docker=read", "--set", "exec=/usr/bin/df")
	if err != nil {
		t.Fatalf("set: %v\n%s", err, out)
	}
	dc, err := st.DeviceCeilings().Get(t.Context(), "pi")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Logs       []string `json:"logs"`
		Exec       []string `json:"exec"`
		DockerRead bool     `json:"dockerRead"`
	}
	if err := json.Unmarshal(dc.Ceiling, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Logs) != 3 || len(got.Exec) != 1 || !got.DockerRead || !strings.HasPrefix(dc.UpdatedBy, "admin/") {
		t.Errorf("stored %s by %s", dc.Ceiling, dc.UpdatedBy)
	}
	entries, err := st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[0].Action != string(policy.DeviceCapabilitiesRaise) || entries[0].Decision != policy.Allow {
		t.Errorf("audit = %+v, want an allowed raise (exec)", entries)
	}

	for _, bad := range [][]string{{"--set", "exec=on"}, {"--set", "shell=maybe"}, {"--set", "root=on"}, {"--set", "logs"}, {"--set", "exec=df"}} {
		if _, err := execute(t, append([]string{"device", "capabilities", "pi", "--data-dir", dir}, bad...)...); err == nil {
			t.Errorf("%v: want an error", bad)
		}
	}
	if _, err := execute(t, "device", "capabilities", "ghost", "--data-dir", dir); err == nil {
		t.Error("unknown device: want an error")
	}
}
