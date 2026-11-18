// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// eventKinds are the built-in triggers and actions over devs and agents.
func eventKinds(devs DeviceEvents, agents Agents, hc *http.Client) Kinds {
	k := actionKinds(ActionDeps{Agents: agents, HTTP: hc})
	maps.Copy(k.Triggers, Triggers(TriggerDeps{Devices: devs}))
	return k
}

const restartOfflineYAML = `id: revive
triggers:
  - id: down
    type: device
    to: offline
actions:
  - id: kick
    type: restart
    device: "{{ .Trigger.Device }}"
    service: systemd:hearth-agent.service
`

// The issue's done-when: a device trigger with no device filter runs an
// action on the device that went offline.
func TestDeviceOfflineTriggerTargetsThatDevice(t *testing.T) {
	devs := &fakeDevices{ch: make(chan DeviceEvent)}
	agents := &fakeAgents{result: &agentv1.ExecResult{}}
	h := newHarness(t, restartOfflineYAML, eventKinds(devs, agents, nil))

	devs.ch <- DeviceEvent{ID: "dev-pi", Name: "pi", Hostname: "pi.lan", Online: false}
	eventually(t, "the run recorded", func() bool { return len(h.rec.all()) == 1 })

	run := h.rec.all()[0]
	if run.Status != StatusSucceeded {
		t.Fatalf("run = %+v", run)
	}
	agents.mu.Lock()
	devices := slices.Clone(agents.devs)
	agents.mu.Unlock()
	if !slices.Equal(devices, []string{"dev-pi"}) {
		t.Errorf("restart sent to %v, want [dev-pi]", devices)
	}
	// Policy decided on, and the audit log names, the rendered device.
	if e := h.audit.all(); len(e) != 1 || e[0].Target != "dev-pi" || e[0].Action != string(policy.AutomationRestart) {
		t.Errorf("audit = %+v", e)
	}
	// Run history keeps what the trigger passed.
	got := steps(t, run)[0]
	if got.ID != "down" || got.Type != "device" || got.Status != "fired" ||
		got.Data["Device"] != "dev-pi" || got.Data["Name"] != "pi" || got.Data["State"] != "offline" {
		t.Errorf("trigger step = %+v", got)
	}
}

func TestWebhookTemplates(t *testing.T) {
	type req struct{ body, title string }
	var (
		mu  sync.Mutex
		got []req
	)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, req{string(b), r.Header.Get("Title")})
		mu.Unlock()
	}))
	defer srv.Close()
	devs := &fakeDevices{ch: make(chan DeviceEvent)}
	h := newHarness(t, `id: notify
triggers:
  - id: up
    type: device
    to: online
actions:
  - type: webhook
    url: `+srv.URL+`/secret-topic
    headers: {Title: "{{ .Trigger.Name }} is back"}
    body: "{{ .Trigger.Hostname }} is {{ .Trigger.State }} ({{ .Trigger.Type }} trigger {{ .Trigger.ID }})"
`, eventKinds(devs, nil, srv.Client()))

	devs.ch <- DeviceEvent{ID: "d1", Name: "nas", Hostname: "nas.lan", Online: true}
	eventually(t, "the run recorded", func() bool { return len(h.rec.all()) == 1 })
	mu.Lock()
	defer mu.Unlock()
	want := []req{{"nas.lan is online (device trigger up)", "nas is back"}}
	if !slices.Equal(got, want) {
		t.Errorf("requests = %+v, want %+v", got, want)
	}
	// The audit log still names the site only.
	if e := h.audit.all(); len(e) != 1 || strings.Contains(e[0].Target, "secret") {
		t.Errorf("audit = %+v", e)
	}
}

func TestTemplateLoadErrors(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{
			name: "parse error at its line",
			yaml: "id: a\ntriggers: [{type: manual}]\nactions:\n  - type: log\n    message: \"{{ .Trigger.ID \"\n",
			want: "a.yaml:5: message: template: message:1: unclosed action",
		},
		{
			name: "unknown function",
			yaml: "id: a\ntriggers: [{type: manual}]\nactions:\n  - type: log\n    message: \"{{ env \\\"HOME\\\" }}\"\n",
			want: `a.yaml:5: message: template: message:1: function "env" not defined`,
		},
		{
			name: "field the trigger does not have",
			yaml: "id: a\ntriggers: [{id: by-hand, type: manual}]\nactions:\n  - id: kick\n    type: restart\n    service: docker:x\n    device: \"{{ .Trigger.Device }}\"\n",
			want: "a.yaml:7: action kick: device: .Trigger.Device: no such field (when trigger by-hand fires)",
		},
		{
			name: "field one of several triggers does not have",
			yaml: "id: a\ntriggers:\n  - {id: down, type: device, to: offline}\n  - {id: nightly, type: schedule, cron: '@daily'}\n" +
				"actions:\n  - type: webhook\n    url: https://ntfy.sh/x\n    body: \"{{ .Trigger.Name }} down\"\n",
			want: "a.yaml:8: action webhook-1: body: .Trigger.Name: no such field (when trigger nightly fires)",
		},
		{
			name: "header template",
			yaml: "id: a\ntriggers: [{type: manual}]\nactions:\n  - type: webhook\n    url: https://ntfy.sh/x\n    headers:\n      Title: \"{{ .Trigger.Value }}\"\n",
			want: "a.yaml:7: action webhook-1: headers.Title: .Trigger.Value: no such field",
		},
		{
			name: "lowercase key",
			yaml: "id: a\ntriggers: [{type: manual}]\nactions: [{type: log, message: \"{{ .trigger.id }}\"}]\n",
			want: "a.yaml:3: action log-1: message: .trigger.id: no such field",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("a.yaml", []byte(tc.yaml), eventKinds(nil, nil, nil))
			wantErrContains(t, err, tc.want)
		})
	}
}

func TestTemplateMissingKeyAtRunIsAnError(t *testing.T) {
	// A trigger that fires without a field its sample promised: the action
	// fails rather than render an empty device.
	text, err := parseTestText("{{ .Trigger.Device }}")
	if err != nil {
		t.Fatal(err)
	}
	_, err = text.Render(Event{TriggerID: "t", Data: map[string]any{}})
	wantErrContains(t, err, "device: .Trigger.Device: no such field")

	a := &agentAction{agents: &fakeAgents{}, device: text, req: func() *agentv1.ExecRequest { return &agentv1.ExecRequest{} }}
	err = a.Run(context.Background(), Event{Data: map[string]any{"Device": " "}})
	wantErrContains(t, err, "is empty for this event")
}

func parseTestText(raw string) (Text, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte("device: x"), &doc); err != nil {
		return Text{}, err
	}
	return Params{node: doc.Content[0]}.Text(raw, "device")
}

func TestTriggerData(t *testing.T) {
	devs := &fakeDevices{ch: make(chan DeviceEvent)}
	w := watch(t, mustBuildTrigger(t, TriggerDeps{Devices: devs}, "type: device\nto: offline"))
	devs.ch <- DeviceEvent{ID: "d2", Name: "pi", Hostname: "pi.lan"}
	devs.ch <- DeviceEvent{ID: "none", Online: true} // handled after the first
	want := map[string]any{"Device": "d2", "Name": "pi", "Hostname": "pi.lan", "State": "offline"}
	if got := w.fired(); len(got) != 1 || !maps.Equal(got[0], want) {
		t.Errorf("fired %v, want %v", got, want)
	}

	clock := newFakeClock(time.Now())
	tr := mustBuildTrigger(t, TriggerDeps{Clock: clock}, "type: tcp\naddress: 127.0.0.1:1")
	w = watch(t, tr)
	clock.waitForWaiter(t)
	got := w.fired()
	if len(got) != 1 || got[0]["Target"] != "127.0.0.1:1" || got[0]["Error"] == "" {
		t.Errorf("tcp check fired %v", got)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got[0])), slices.Sorted(maps.Keys(tr.Sample()))) {
		t.Errorf("fired keys %v differ from the sample %v", got[0], tr.Sample())
	}
}

func TestPlanShowsTemplatesUnrendered(t *testing.T) {
	a, err := Parse("revive.yaml", []byte(restartOfflineYAML), eventKinds(nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := Plan(&b, a); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"templates see: .Trigger.ID, .Trigger.Type, .Trigger.At, .Trigger.Device, .Trigger.Hostname, .Trigger.Name, .Trigger.State",
		"restart systemd:hearth-agent.service on {{ .Trigger.Device }}",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("plan lacks %q:\n%s", want, b.String())
		}
	}
}
