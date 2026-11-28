// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// ProtocolVersion is the version of the plugin protocol this SDK speaks.
const ProtocolVersion = 1

// maxLine is the longest line the SDK reads from the hub.
const maxLine = 1 << 20

// Device is a device a plugin reports, with its entities.
type Device struct {
	// ID is unique within the plugin: letters, digits, '.', '_' and '-';
	// up to 64.
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind,omitempty"`
	Entities []Entity `json:"entities"`
}

// Entity is one thing of a device: a sensor, a switch.
type Entity struct {
	// ID is unique within the device, as a device's ID is.
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
	// Unit is the state's unit, such as W or °C.
	Unit string `json:"unit,omitempty"`
	// State is any JSON value, up to 4 KiB; nil if none yet.
	State any `json:"state"`
}

// Command is a command the hub sends, once policy allowed it. It is always
// one the plugin's manifest declares.
type Command struct {
	Name string
	// Device is the device the command is for, if the caller named one.
	Device string
	// Args are the command's arguments: a JSON object, or empty.
	Args json.RawMessage
}

// ErrNotStarted is a state or devices update sent before the hub greeted
// the plugin: it is dropped.
var ErrNotStarted = errors.New("sdk: the hub has not greeted the plugin yet")

// Plugin is a Hearth plugin: fill in its fields and call Run. The same
// plugin builds as an exec plugin (any GOOS) and as a WASM plugin
// (GOOS=wasip1 GOARCH=wasm).
type Plugin struct {
	// Name is the name in the plugin's manifest. Empty means the
	// HEARTH_PLUGIN environment variable, which the hub sets.
	Name string
	// Version is the plugin's own version.
	Version string
	// Discover returns every device of the plugin; nil reports none. It
	// needs the discover capability in the manifest.
	Discover func() ([]Device, error)
	// Command runs a command and returns its output, up to 64 KiB, or why
	// it failed. It needs the command capability in the manifest.
	Command func(Command) (string, error)

	mu      sync.Mutex
	w       io.Writer
	greeted bool
}

// message is one line of the protocol, in either direction.
type message struct {
	Type     string          `json:"type"`
	ID       string          `json:"id,omitempty"`
	Protocol int             `json:"protocol,omitempty"`
	Name     string          `json:"name,omitempty"`
	Version  string          `json:"version,omitempty"`
	Devices  *[]Device       `json:"devices,omitempty"`
	Device   string          `json:"device,omitempty"`
	Entity   string          `json:"entity,omitempty"`
	State    any             `json:"state,omitempty"`
	Command  string          `json:"command,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	OK       bool            `json:"ok,omitempty"`
	Output   string          `json:"output,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// Run serves the hub on stdin and stdout until the hub closes stdin.
func (p *Plugin) Run() error { return p.Serve(stdin(), os.Stdout) }

// Serve serves the hub's messages read from r, writing the plugin's to w,
// until r ends. Messages are handled one at a time; SetState and SetDevices
// may be called from other goroutines meanwhile.
func (p *Plugin) Serve(r io.Reader, w io.Writer) error {
	p.mu.Lock()
	p.w, p.greeted = w, false
	p.mu.Unlock()
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		b, err := readLine(br)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("sdk: read: %w", err)
		}
		if len(b) == 0 {
			continue
		}
		var m message
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("sdk: a line from the hub is not JSON: %w", err)
		}
		if err := p.handle(m); err != nil {
			return err
		}
	}
}

func readLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) > maxLine+1 {
			return nil, fmt.Errorf("a line is longer than %d bytes", maxLine)
		}
		switch {
		case err == nil:
			return append(buf, chunk[:len(chunk)-1]...), nil
		case errors.Is(err, bufio.ErrBufferFull):
			buf = append(buf, chunk...)
		default:
			return nil, err
		}
	}
}

// handle answers one message of the hub. Types it does not know are
// ignored: newer hubs may send more.
func (p *Plugin) handle(m message) error {
	switch m.Type {
	case "hello":
		name := p.Name
		if name == "" {
			name = os.Getenv("HEARTH_PLUGIN")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.greeted = true
		return p.writeLocked(message{Type: "hello", Protocol: ProtocolVersion, Name: name, Version: p.Version})
	case "ping":
		return p.write(message{Type: "pong", ID: m.ID})
	case "discover":
		devs := []Device{}
		if p.Discover != nil {
			d, err := p.Discover()
			if err != nil {
				return fmt.Errorf("sdk: discover: %w", err)
			}
			devs = append(devs, d...)
		}
		return p.write(message{Type: "devices", ID: m.ID, Devices: &devs})
	case "command":
		res := message{Type: "result", ID: m.ID}
		if p.Command == nil {
			res.Error = "the plugin has no commands"
		} else if out, err := p.Command(Command{Name: m.Command, Device: m.Device, Args: m.Args}); err != nil {
			res.Error = err.Error()
		} else {
			res.OK, res.Output = true, out
		}
		return p.write(res)
	}
	return nil
}

// SetState pushes an entity's new state; it needs the state capability in
// the manifest. The hub drops a state of a device or entity the plugin has
// not reported.
func (p *Plugin) SetState(device, entity string, state any) error {
	return p.push(message{Type: "state", Device: device, Entity: entity, State: state})
}

// SetDevices reports the plugin's devices, replacing those before, without
// waiting for the hub to ask; it needs the discover capability.
func (p *Plugin) SetDevices(devs []Device) error {
	if devs == nil {
		devs = []Device{}
	}
	return p.push(message{Type: "devices", Devices: &devs})
}

func (p *Plugin) push(m message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.greeted {
		return ErrNotStarted
	}
	return p.writeLocked(m)
}

func (p *Plugin) write(m message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.writeLocked(m)
}

func (p *Plugin) writeLocked(m message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("sdk: %s: %w", m.Type, err)
	}
	if _, err := p.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("sdk: write: %w", err)
	}
	return nil
}
