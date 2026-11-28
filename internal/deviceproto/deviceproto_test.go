// SPDX-License-Identifier: AGPL-3.0-only

package deviceproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidID(t *testing.T) {
	tests := map[string]bool{
		"kitchen": true, "esp32-a1": true, "a_b": true, "0": true, strings.Repeat("a", 64): true,
		"": false, "Kitchen": false, "-a": false, "_a": false, "a/b": false, "a+": false, "a#": false,
		"a b": false, "a:b": false, "a.b": false, strings.Repeat("a", 65): false,
	}
	for id, want := range tests {
		if got := ValidID(id); got != want {
			t.Errorf("ValidID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestSplitTopic(t *testing.T) {
	tests := []struct {
		topic, id, kind string
		ok              bool
	}{
		{"hearth/v1/kitchen/announce", "kitchen", KindAnnounce, true},
		{"hearth/v1/kitchen/command", "kitchen", KindCommand, true},
		{"hearth/v1/kitchen/result", "kitchen", KindResult, true},
		{"hearth/v1/kitchen/other", "", "", false},
		{"hearth/v1/kitchen/state/x", "", "", false},
		{"hearth/v1/Kitchen/state", "", "", false},
		{"hearth/v1/kitchen", "", "", false},
		{"hearth/v2/kitchen/state", "", "", false},
		{"sensors/kitchen/state", "", "", false},
	}
	for _, tt := range tests {
		id, kind, ok := SplitTopic(tt.topic)
		if id != tt.id || kind != tt.kind || ok != tt.ok {
			t.Errorf("SplitTopic(%q) = %q %q %v, want %q %q %v", tt.topic, id, kind, ok, tt.id, tt.kind, tt.ok)
		}
	}
	for topic, want := range map[string]bool{
		"hearth/v1": true, "hearth/v1/": true, "hearth/v1/x/y/z": true,
		"hearth/v10/x": false, "hearth": false, "hearth/dev1/x": false, "sensors/x": false,
	} {
		if got := InNamespace(topic); got != want {
			t.Errorf("InNamespace(%q) = %v, want %v", topic, got, want)
		}
	}
}

const goodAnnounce = `{"v":1,"name":"Kitchen sensor","model":"ESP32-DevKitC","manufacturer":"Espressif","sw_version":"1.0.0",
"entities":[{"id":"temperature","kind":"sensor","name":"Temperature","unit":"°C"},{"id":"relay","kind":"switch"}],
"commands":[{"name":"relay.set","description":"Turn the relay on or off"}],"future_field":true}`

func TestParseValid(t *testing.T) {
	m, err := Parse("kitchen", KindAnnounce, []byte(goodAnnounce))
	if err != nil {
		t.Fatal(err)
	}
	if a := m.Announce; a.Name != "Kitchen sensor" || len(a.Entities) != 2 || a.Commands[0].Name != "relay.set" {
		t.Fatalf("announce = %+v", a)
	}
	m, err = Parse("kitchen", KindState, []byte(`{"v":1,"state":{"relay":true,"temperature":21.5,"mode":"auto","x":null}}`))
	if err != nil || m.Values["relay"] != true || m.Values["temperature"] != 21.5 {
		t.Fatalf("state = %+v, %v", m.Values, err)
	}
	m, err = Parse("kitchen", KindTelemetry, []byte(`{"v":1,"values":{"rssi":-61,"heap_free":182000}}`))
	if err != nil || m.Values["rssi"] != float64(-61) {
		t.Fatalf("telemetry = %+v, %v", m.Values, err)
	}
	m, err = Parse("kitchen", KindAvailability, []byte(`{"v":1,"status":"online"}`))
	if err != nil || !m.Online {
		t.Fatalf("availability = %+v, %v", m, err)
	}
	m, err = Parse("kitchen", KindResult, []byte(`{"v":1,"id":"0123456789abcdef0123456789abcdef","ok":true,"message":"relay on"}`))
	if err != nil || !m.Result.OK || m.Result.Message != "relay on" {
		t.Fatalf("result = %+v, %v", m.Result, err)
	}
}

func TestParseRefuses(t *testing.T) {
	entities := make([]string, MaxEntities+1)
	for i := range entities {
		entities[i] = fmt.Sprintf(`{"id":"e%d","kind":"sensor"}`, i)
	}
	tests := []struct{ name, kind, payload string }{
		{"malformed JSON", KindAnnounce, `{"v":1,`},
		{"not an object", KindAnnounce, `[1,2]`},
		{"trailing data", KindState, `{"v":1,"state":{"a":1}} {}`},
		{"no version", KindAnnounce, `{"name":"x"}`},
		{"version 2", KindAnnounce, `{"v":2}`},
		{"oversize", KindAnnounce, `{"v":1,"name":"` + strings.Repeat("x", MaxPayload) + `"}`},
		{"long name", KindAnnounce, `{"v":1,"name":"` + strings.Repeat("x", MaxText+1) + `"}`},
		{"bad entity id", KindAnnounce, `{"v":1,"entities":[{"id":"A/B","kind":"sensor"}]}`},
		{"unknown entity kind", KindAnnounce, `{"v":1,"entities":[{"id":"a","kind":"light"}]}`},
		{"duplicate entity", KindAnnounce, `{"v":1,"entities":[{"id":"a","kind":"sensor"},{"id":"a","kind":"switch"}]}`},
		{"too many entities", KindAnnounce, `{"v":1,"entities":[` + strings.Join(entities, ",") + `]}`},
		{"bad command name", KindAnnounce, `{"v":1,"commands":[{"name":".x"}]}`},
		{"duplicate command", KindAnnounce, `{"v":1,"commands":[{"name":"x"},{"name":"x"}]}`},
		{"empty state", KindState, `{"v":1,"state":{}}`},
		{"nested state", KindState, `{"v":1,"state":{"a":{"b":1}}}`},
		{"array state", KindState, `{"v":1,"state":{"a":[1]}}`},
		{"string telemetry", KindTelemetry, `{"v":1,"values":{"a":"1"}}`},
		{"bad availability", KindAvailability, `{"v":1,"status":"maybe"}`},
		{"result without id", KindResult, `{"v":1,"ok":true}`},
		{"result with a bad id", KindResult, `{"v":1,"id":"xyz","ok":true}`},
		{"a device does not publish commands", KindCommand, `{"v":1,"id":"0123456789abcdef","command":"x"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse("kitchen", tt.kind, []byte(tt.payload)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCheckCommand(t *testing.T) {
	tests := []struct {
		name, command, params string
		ok                    bool
	}{
		{"no params", "restart", "", true},
		{"object params", "relay.set", `{"on":true}`, true},
		{"bad name", "Relay", "", false},
		{"array params", "relay.set", `[true]`, false},
		{"null params", "relay.set", `null`, false},
		{"long params", "relay.set", `{"a":"` + strings.Repeat("x", MaxParams) + `"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckCommand(tt.command, json.RawMessage(tt.params))
			if (err == nil) != tt.ok {
				t.Fatalf("CheckCommand = %v, want ok %v", err, tt.ok)
			}
		})
	}
}
