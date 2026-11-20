// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Message types of protocol version 1. Every line on the plugin's stdin and
// stdout is one JSON object with a "type".
const (
	// typeHello opens a session: the hub sends its protocol version, the
	// plugin answers with its own, its name and its version.
	typeHello = "hello"
	// typePing asks a plugin to show it is alive: it answers typePong with
	// the same id.
	typePing = "ping"
	typePong = "pong"
	// typeDiscover asks a plugin for its devices: it answers typeDevices
	// with the same id. A plugin may also send typeDevices on its own, with
	// no id, whenever its devices change.
	typeDiscover = "discover"
	typeDevices  = "devices"
	// typeState is an entity's new state, pushed by the plugin.
	typeState = "state"
	// typeCommand runs a declared command: the plugin answers typeResult
	// with the same id.
	typeCommand = "command"
	typeResult  = "result"
)

// Limits on what a plugin reports.
const (
	maxDevices  = 256
	maxEntities = 64
	maxName     = 128
	maxState    = 4 << 10
	maxOutput   = 64 << 10
	maxArgs     = 16 << 10
	// maxStderrLine and stderrLines bound the tail of a plugin's stderr the
	// hub keeps.
	maxStderrLine = 512
	stderrLines   = 20
)

// message is one line of the protocol, in either direction.
type message struct {
	Type     string          `json:"type"`
	ID       string          `json:"id,omitempty"`
	Protocol int             `json:"protocol,omitempty"`
	Name     string          `json:"name,omitempty"`
	Version  string          `json:"version,omitempty"`
	Devices  []Device        `json:"devices,omitempty"`
	Device   string          `json:"device,omitempty"`
	Entity   string          `json:"entity,omitempty"`
	State    json.RawMessage `json:"state,omitempty"`
	Command  string          `json:"command,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	OK       bool            `json:"ok,omitempty"`
	Output   string          `json:"output,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// Device is a device a plugin reports.
type Device struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind,omitempty"`
	Entities []Entity `json:"entities"`
}

// Entity is one thing of a device a plugin reports: a sensor, a switch.
type Entity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
	Unit string `json:"unit,omitempty"`
	// State is the entity's last state, any JSON value; null if none yet.
	State json.RawMessage `json:"state"`
}

// validDevices checks the devices a plugin reports.
func validDevices(devs []Device) error {
	if len(devs) > maxDevices {
		return fmt.Errorf("more than %d devices", maxDevices)
	}
	seen := make(map[string]bool, len(devs))
	for _, d := range devs {
		if !idRE.MatchString(d.ID) {
			return fmt.Errorf("invalid device id %.64q", d.ID)
		}
		if seen[d.ID] {
			return fmt.Errorf("device %q reported twice", d.ID)
		}
		seen[d.ID] = true
		if err := validText(d.Name, d.Kind); err != nil {
			return fmt.Errorf("device %q: %w", d.ID, err)
		}
		if len(d.Entities) > maxEntities {
			return fmt.Errorf("device %q: more than %d entities", d.ID, maxEntities)
		}
		ents := make(map[string]bool, len(d.Entities))
		for _, e := range d.Entities {
			if !idRE.MatchString(e.ID) {
				return fmt.Errorf("device %q: invalid entity id %.64q", d.ID, e.ID)
			}
			if ents[e.ID] {
				return fmt.Errorf("device %q: entity %q reported twice", d.ID, e.ID)
			}
			ents[e.ID] = true
			if err := validText(e.Name, e.Kind, e.Unit); err != nil {
				return fmt.Errorf("device %q entity %q: %w", d.ID, e.ID, err)
			}
			if len(e.State) > maxState {
				return fmt.Errorf("device %q entity %q: state larger than %d bytes", d.ID, e.ID, maxState)
			}
		}
	}
	return nil
}

func validText(ss ...string) error {
	for _, s := range ss {
		if len(s) > maxName || !utf8.ValidString(s) {
			return errors.New("name, kind or unit too long or not UTF-8")
		}
	}
	return nil
}

// truncate cuts s to at most n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
