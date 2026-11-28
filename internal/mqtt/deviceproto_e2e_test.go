// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/deviceproto"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// protocolHub is a broker with the hub's Device Protocol handler on a real
// store, registry and policy engine.
type protocolHub struct {
	tb  *testBroker
	st  *store.Store
	reg *hub.Registry
	pol *policy.Engine
	p   *hub.DeviceProtocol
}

func startProtocolHub(t *testing.T) *protocolHub {
	t.Helper()
	st := storetest.Open(t)
	reg := hub.NewRegistry(hub.RegistryConfig{Store: st})
	pol := policy.New(st.Audit())
	p := hub.NewDeviceProtocol(hub.DeviceProtocolConfig{
		Store: st, Registry: reg, Policy: pol,
		Flush: 20 * time.Millisecond, Seen: 50 * time.Millisecond, CommandTimeout: 2 * time.Second,
	})
	tb := startBrokerConfig(t, protocolYAML, func(c *Config) { c.Protocol = p })
	p.SetBus(tb.b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return &protocolHub{tb: tb, st: st, reg: reg, pol: pol, p: p}
}

// waitDevice waits until the store's device id satisfies ok.
func (h *protocolHub) waitDevice(t *testing.T, id string, ok func(store.Device) bool) store.Device {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		d, err := h.st.Devices().Get(t.Context(), id)
		if err == nil && ok(d) {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("device %s: %+v, %v", id, d, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func protocolFacts(t *testing.T, d store.Device) hub.ProtocolFacts {
	t.Helper()
	var doc struct {
		DeviceProtocol hub.ProtocolFacts `json:"device_protocol"`
	}
	if err := json.Unmarshal(d.Facts, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.DeviceProtocol
}

// answer reads the next command kitchen gets and answers it.
func answer(t *testing.T, c *client, ok bool, message string) deviceproto.Command {
	t.Helper()
	topic, payload := c.next()
	if topic != "hearth/v1/kitchen/command" {
		t.Fatalf("got a message on %s", topic)
	}
	var cmd deviceproto.Command
	if err := json.Unmarshal([]byte(payload), &cmd); err != nil {
		t.Fatal(err)
	}
	res, _ := json.Marshal(deviceproto.Result{V: 1, ID: cmd.ID, OK: ok, Message: message})
	c.publish("hearth/v1/kitchen/result", string(res))
	return cmd
}

type commandOutcome struct {
	res hub.CommandResult
	err error
}

func (h *protocolHub) command(id, name, params string) <-chan commandOutcome {
	out := make(chan commandOutcome, 1)
	go func() {
		res, err := h.p.Command(context.Background(), policy.ActorWeb, "127.0.0.1", id, hub.CommandRequest{
			Command: name, Params: json.RawMessage(params),
		})
		out <- commandOutcome{res, err}
	}()
	return out
}

// TestDeviceProtocolEndToEnd: a device that announces itself over MQTT
// appears in the registry, online, with its state and telemetry; a command
// goes through policy, is audited, reaches it and comes back with its result;
// and it goes offline when it disconnects.
func TestDeviceProtocolEndToEnd(t *testing.T) {
	h := startProtocolHub(t)
	events, unsubscribe := h.reg.SubscribeUI()
	defer unsubscribe()
	id := store.ProtocolDeviceID("kitchen")

	kitchen := connected(t, h.tb, "kitchen", "kitchen")
	if rc := kitchen.subscribe("hearth/v1/kitchen/command"); rc != 0 {
		t.Fatalf("subscribe: %#x", rc)
	}
	kitchen.publish("hearth/v1/kitchen/announce", announceJSON)
	d := h.waitDevice(t, id, func(d store.Device) bool { return d.Status == store.StatusOnline })
	if d.Name != "Kitchen" || d.Hostname != "kitchen" || d.Labels[store.LabelSource] != store.SourceDeviceProtocol {
		t.Fatalf("device = %+v", d)
	}
	select {
	case e := <-events:
		if e.Type != hub.EventDeviceOnline || e.Device.ID != id {
			t.Fatalf("event = %s %s", e.Type, e.Device.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no device.online event for the UI")
	}

	kitchen.publish("hearth/v1/kitchen/state", `{"v":1,"state":{"relay":true,"unannounced":1}}`)
	kitchen.publish("hearth/v1/kitchen/telemetry", `{"v":1,"values":{"rssi":-61}}`)
	d = h.waitDevice(t, id, func(d store.Device) bool {
		f := protocolFacts(t, d)
		return f.State["relay"] == true && f.Telemetry["rssi"] == float64(-61)
	})
	if f := protocolFacts(t, d); f.State["unannounced"] != nil || f.CommandClass != "dangerous" || len(f.Commands) != 1 {
		t.Fatalf("facts = %+v", f)
	}

	// A command round trip, through policy.
	out := h.command(id, "relay.set", `{"on":true}`)
	cmd := answer(t, kitchen, true, "relay on")
	if cmd.Command != "relay.set" || string(cmd.Params) != `{"on":true}` || cmd.V != 1 {
		t.Fatalf("command = %+v", cmd)
	}
	got := <-out
	if got.err != nil || !got.res.OK || got.res.Message != "relay on" || got.res.ID != cmd.ID || got.res.Class != "dangerous" {
		t.Fatalf("Command = %+v, %v", got.res, got.err)
	}
	entries, err := h.st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	for _, e := range entries {
		if e.Action == string(policy.DeviceCommand) {
			results = append(results, e.Decision+":"+e.Result)
			if e.Target != "Kitchen/relay.set" || strings.Contains(string(e.Detail), `"on"`) {
				t.Fatalf("audit entry %+v %s", e, e.Detail)
			}
		}
	}
	if strings.Join(results, ",") != "allow:ok" && strings.Join(results, ",") != "allow:ok,allow:started" {
		t.Fatalf("audit of device.command = %v", results)
	}

	// The device says it failed.
	out = h.command(id, "relay.set", "")
	answer(t, kitchen, false, "relay stuck")
	if got := <-out; !errors.Is(got.err, hub.ErrProtocolFailed) || got.res.OK {
		t.Fatalf("Command = %+v, %v, want failed", got.res, got.err)
	}

	// The device goes away.
	_ = kitchen.conn.Close()
	h.waitDevice(t, id, func(d store.Device) bool { return d.Status == store.StatusOffline })
	if _, err := h.p.Command(t.Context(), policy.ActorWeb, "127.0.0.1", id, hub.CommandRequest{Command: "relay.set"}); !errors.Is(err, hub.ErrProtocolUnavailable) {
		t.Fatalf("Command to a gone device = %v, want unavailable", err)
	}
}

// TestDeviceProtocolCommandRefusals: nothing reaches the device unless the
// device announced the command and policy allows it, and another device
// cannot answer for it.
func TestDeviceProtocolCommandRefusals(t *testing.T) {
	h := startProtocolHub(t)
	id := store.ProtocolDeviceID("kitchen")
	kitchen := connected(t, h.tb, "kitchen", "kitchen")
	kitchen.subscribe("hearth/v1/kitchen/command")
	kitchen.publish("hearth/v1/kitchen/announce", announceJSON)
	h.waitDevice(t, id, func(d store.Device) bool { return d.Status == store.StatusOnline })
	ctx := t.Context()

	if _, err := h.p.Command(ctx, policy.ActorWeb, "x", id, hub.CommandRequest{Command: "reboot"}); !errors.Is(err, hub.ErrProtocolUnknownCommand) {
		t.Fatalf("undeclared command: %v", err)
	}
	if _, err := h.p.Command(ctx, policy.ActorWeb, "x", id, hub.CommandRequest{Command: "relay.set", Params: json.RawMessage(`[1]`)}); !errors.Is(err, hub.ErrProtocolBadCommand) {
		t.Fatalf("bad params: %v", err)
	}
	if _, err := h.p.Command(ctx, policy.ActorWeb, "x", "0000000000000000", hub.CommandRequest{Command: "relay.set"}); !errors.Is(err, hub.ErrProtocolDeviceNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
	// An enrolled device is not a protocol device.
	if err := h.st.Devices().Upsert(ctx, store.Device{ID: "cdb1a1c4399bb039bdc3", Name: "pi", Status: store.StatusOnline}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.Command(ctx, policy.ActorWeb, "x", "cdb1a1c4399bb039bdc3", hub.CommandRequest{Command: "relay.set"}); !errors.Is(err, hub.ErrProtocolDeviceNotFound) {
		t.Fatalf("an agent's device: %v", err)
	}
	// Automations and MCP clients may not send commands at all.
	if _, err := h.p.Command(ctx, policy.ActorAutomation, "a1", id, hub.CommandRequest{Command: "relay.set"}); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("automation: %v", err)
	}
	// A policy that denies dangerous actions denies every command.
	h.pol.SetConfig(policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	if _, err := h.p.Command(ctx, policy.ActorWeb, "x", id, hub.CommandRequest{Command: "relay.set"}); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("denied by policy: %v", err)
	}
	kitchen.none()
	entries, err := h.st.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	denials := 0
	for _, e := range entries {
		if e.Action == string(policy.DeviceCommand) {
			if e.Decision != "deny" {
				t.Fatalf("audit entry %+v, want only denials", e)
			}
			denials++
		}
	}
	if denials != 2 {
		t.Fatalf("%d denials audited, want 2", denials)
	}

	// garage answers kitchen's command on its own result topic: the hub
	// does not take it, and the command times out.
	h.pol.SetConfig(policy.Config{})
	garage := connected(t, h.tb, "garage", "garage")
	garage.subscribe("hearth/v1/kitchen/command") // the clients file lets garage read it
	out := h.command(id, "relay.set", "")
	_, payload := garage.next()
	var cmd deviceproto.Command
	if err := json.Unmarshal([]byte(payload), &cmd); err != nil {
		t.Fatal(err)
	}
	res, _ := json.Marshal(deviceproto.Result{V: 1, ID: cmd.ID, OK: true})
	garage.publish("hearth/v1/garage/result", string(res))
	garage.publish("hearth/v1/kitchen/result", string(res)) // refused by the ACL
	if got := <-out; !errors.Is(got.err, hub.ErrProtocolTimeout) {
		t.Fatalf("Command = %+v, %v, want a timeout", got.res, got.err)
	}
}

// TestDeviceProtocolDoesNotTakeOverDevices: an announce whose id is held by a
// device that is not a protocol device leaves it alone.
func TestDeviceProtocolDoesNotTakeOverDevices(t *testing.T) {
	h := startProtocolHub(t)
	id := store.ProtocolDeviceID("kitchen")
	if err := h.st.Devices().Upsert(t.Context(), store.Device{ID: id, Name: "other", Status: store.StatusOffline}); err != nil {
		t.Fatal(err)
	}
	kitchen := connected(t, h.tb, "kitchen", "kitchen")
	kitchen.publish("hearth/v1/kitchen/announce", announceJSON)
	kitchen.publish("hearth/v1/kitchen/state", `{"v":1,"state":{"relay":true}}`)
	time.Sleep(200 * time.Millisecond) // the handler flushes every 20 ms
	d, err := h.st.Devices().Get(t.Context(), id)
	if err != nil || d.Name != "other" || d.Status != store.StatusOffline || string(d.Facts) != "{}" {
		t.Fatalf("device = %+v, %v", d, err)
	}
}
