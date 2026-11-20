// SPDX-License-Identifier: AGPL-3.0-only

// Command go-lamp is an example Hearth exec plugin in Go: one virtual lamp
// that can be turned on and off. It speaks protocol version 1 (see
// docs/plugins.md) with the standard library only.
//
// Build it next to its manifest and point the hub at the manifest:
//
//	go build -o lamp . && hearth hub --plugin ./plugin.yaml
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// message is one line of the protocol, in either direction.
type message struct {
	Type     string          `json:"type"`
	ID       string          `json:"id,omitempty"`
	Protocol int             `json:"protocol,omitempty"`
	Name     string          `json:"name,omitempty"`
	Version  string          `json:"version,omitempty"`
	Devices  []device        `json:"devices,omitempty"`
	Device   string          `json:"device,omitempty"`
	Entity   string          `json:"entity,omitempty"`
	State    any             `json:"state,omitempty"`
	Command  string          `json:"command,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	OK       bool            `json:"ok,omitempty"`
	Output   string          `json:"output,omitempty"`
	Error    string          `json:"error,omitempty"`
}

type device struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Entities []entity `json:"entities"`
}

type entity struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	State any    `json:"state"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "go-lamp:", err)
		os.Exit(1)
	}
}

func run() error {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 1<<20)
	enc := json.NewEncoder(os.Stdout) // one object per line, unbuffered
	on := false
	for in.Scan() {
		var m message
		if err := json.Unmarshal(in.Bytes(), &m); err != nil {
			return fmt.Errorf("bad message from the hub: %w", err)
		}
		var reply []message
		switch m.Type {
		case "hello":
			if m.Protocol != 1 {
				return fmt.Errorf("hub speaks protocol %d, this plugin 1", m.Protocol)
			}
			reply = []message{{Type: "hello", Protocol: 1, Name: os.Getenv("HEARTH_PLUGIN"), Version: "0.1.0"}}
		case "ping":
			reply = []message{{Type: "pong", ID: m.ID}}
		case "discover":
			reply = []message{{Type: "devices", ID: m.ID, Devices: []device{{
				ID: "lamp", Name: "Desk lamp", Kind: "light",
				Entities: []entity{{ID: "on", Name: "On", Kind: "switch", State: on}},
			}}}}
		case "command":
			switch m.Command {
			case "turn_on", "turn_off":
				on = m.Command == "turn_on"
				reply = []message{
					{Type: "state", Device: "lamp", Entity: "on", State: on},
					{Type: "result", ID: m.ID, OK: true, Output: fmt.Sprintf("lamp is %s", map[bool]string{true: "on", false: "off"}[on])},
				}
			default:
				reply = []message{{Type: "result", ID: m.ID, Error: "unknown command " + m.Command}}
			}
		}
		// Unknown message types are ignored: newer hubs may send more.
		for _, r := range reply {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
	}
	return in.Err()
}
