// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// exampleKinds are the kinds `hearth automation plan` loads files with.
func exampleKinds(agents Agents) Kinds {
	kinds := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, Triggers(TriggerDeps{}))
	maps.Copy(kinds.Actions, Actions(ActionDeps{Agents: agents}))
	kinds.Actions["script"] = Script(ScriptDeps{})
	return kinds
}

// The shipped self-heal examples load as the hub loads a file and as the web
// UI saves one.
func TestPiholeSelfHealExamples(t *testing.T) {
	files, err := filepath.Glob("../../examples/automations/*.yaml")
	if err != nil || len(files) < 2 {
		t.Fatalf("examples = %v, %v", files, err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Parse(filepath.Base(f), b, exampleKinds(nil))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if _, err := ParseForSave(filepath.Base(f), b, exampleKinds(nil)); err != nil {
			t.Fatalf("%s for save: %v", f, err)
		}
		if a.ID+".yaml" != filepath.Base(f) {
			t.Errorf("%s: id %q does not match the file name", f, a.ID)
		}
	}
	a, err := LoadFile("../../examples/automations/pihole-selfheal.yaml", exampleKinds(nil))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range a.Actions {
		got = append(got, s.Type+"="+string(s.Impl.Policy()))
	}
	want := "check=automation.probe vip_claim=automation.vip.claim notify=automation.notify vip_release=automation.vip.release vip_claim=automation.vip.claim"
	if strings.Join(got, " ") != want {
		t.Errorf("actions = %s, want %s", strings.Join(got, " "), want)
	}
	w, err := LoadFile("../../examples/automations/pihole-watchdog.yaml", exampleKinds(nil))
	if err != nil || !w.Local {
		t.Errorf("watchdog: local = %v, err %v", w != nil && w.Local, err)
	}
}

func TestVIPActionFields(t *testing.T) {
	tests := []struct {
		name, fields, wantErr string
	}{
		{"ok", "device: pi\n    interface: eth0\n    address: 192.168.1.53/24", ""},
		{"no device", "interface: eth0\n    address: 192.168.1.53/24", "device is required"},
		{"no interface", "device: pi\n    address: 192.168.1.53/24", "interface and address are required"},
		{"no prefix", "device: pi\n    interface: eth0\n    address: 192.168.1.53", "IPv4 address with its prefix"},
		{"bad cidr", "device: pi\n    interface: eth0\n    address: 192.168.1.300/24", "IPv4 address with its prefix"},
		{"ipv6", "device: pi\n    interface: eth0\n    address: fd00::53/64", "IPv4 address with its prefix"},
		{"network address", "device: pi\n    interface: eth0\n    address: 192.168.1.0/24", "network or broadcast"},
		{"loopback", "device: pi\n    interface: eth0\n    address: 127.0.0.53/8", "not an address"},
		{"lo", "device: pi\n    interface: lo\n    address: 192.168.1.53/24", "interface"},
		{"flag as interface", "device: pi\n    interface: -all\n    address: 192.168.1.53/24", "interface"},
		{"interface with space", "device: pi\n    interface: \"eth0 up\"\n    address: 192.168.1.53/24", "interface"},
		{"interface too long", "device: pi\n    interface: abcdefghijklmnop\n    address: 192.168.1.53/24", "interface"},
		{"template address", "device: pi\n    interface: eth0\n    address: \"{{ .Trigger.IP }}/24\"", "IPv4 address"},
		{"unknown field", "device: pi\n    interface: eth0\n    address: 192.168.1.53/24\n    dev: eth1", "unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, typ := range []string{"vip_claim", "vip_release"} {
				src := "id: v\ntriggers:\n  - type: manual\nactions:\n  - type: " + typ + "\n    " + tt.fields + "\n"
				_, err := Parse("v.yaml", []byte(src), exampleKinds(nil))
				if tt.wantErr == "" && err != nil {
					t.Fatalf("%s: %v", typ, err)
				}
				if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
					t.Fatalf("%s: err = %v, want %q", typ, err, tt.wantErr)
				}
			}
		})
	}
}

// vipAgents records the requests it is sent and answers each with res.
type vipAgents struct {
	res  *agentv1.ExecResult
	reqs []*agentv1.ExecRequest
}

func (a *vipAgents) Exec(_ context.Context, _ string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	a.reqs = append(a.reqs, req)
	return a.res, nil
}

func TestVIPActionRequest(t *testing.T) {
	for _, release := range []bool{false, true} {
		typ := "vip_claim"
		if release {
			typ = "vip_release"
		}
		agents := &vipAgents{res: &agentv1.ExecResult{}}
		src := "id: v\ntriggers:\n  - type: manual\nactions:\n  - type: " + typ +
			"\n    device: pi\n    interface: eth0\n    address: 192.168.1.53/24\n"
		a, err := Parse("v.yaml", []byte(src), exampleKinds(agents))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Actions[0].Impl.Run(context.Background(), Event{}); err != nil {
			t.Fatal(err)
		}
		want := &agentv1.VirtualIP{Interface: "eth0", Address: "192.168.1.53/24", Release: release}
		if len(agents.reqs) != 1 || !proto.Equal(agents.reqs[0].GetVip(), want) {
			t.Fatalf("%s sent %v, want %v", typ, agents.reqs, want)
		}
		// The agent refusing it, beyond its ceiling, is a denial.
		agents.res = &agentv1.ExecResult{Denied: true, Error: "beyond"}
		if err := a.Actions[0].Impl.Run(context.Background(), Event{}); !errors.Is(err, policy.ErrBeyondCeiling) {
			t.Errorf("%s refused by the agent: err = %v, want ErrBeyondCeiling", typ, err)
		}
	}
}
