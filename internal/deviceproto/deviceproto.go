// SPDX-License-Identifier: AGPL-3.0-only

// Package deviceproto is the Hearth Device Protocol v1 (docs/spec/device-protocol-v1.md):
// JSON messages a small device publishes on its own MQTT topics, under
// hearth/v1/<device>/, to appear in the hub's registry, report its state and
// telemetry, and receive commands. It only names the topics and parses and
// checks the messages; the broker (internal/mqtt) enforces who may publish
// them, and the hub (internal/hub) acts on them.
package deviceproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

// Version is the protocol's major version: the topic's second level and
// every message's "v".
const Version = 1

// Prefix is the protocol's topic namespace. A device's topics are
// Prefix + <device id> + "/" + <kind>.
const Prefix = "hearth/v1/"

// Message kinds: the last level of a topic.
const (
	// Device to hub.
	KindAnnounce     = "announce"
	KindState        = "state"
	KindTelemetry    = "telemetry"
	KindAvailability = "availability"
	KindResult       = "result"
	// Hub to device.
	KindCommand = "command"
)

// Limits. A message beyond any of them is refused whole.
const (
	// MaxPayload is the largest message, of any kind, in bytes.
	MaxPayload = 16 << 10
	// MaxParams is the largest params object of a command, in bytes.
	MaxParams = 4 << 10
	// MaxIDLength bounds device, entity and command ids.
	MaxIDLength = 64
	// MaxEntities and MaxCommands bound an announce.
	MaxEntities = 64
	MaxCommands = 32
	// MaxValues bounds the keys of a state or telemetry message.
	MaxValues = 64
	// MaxText bounds names, units, descriptions, model strings, string
	// state values and result messages, in bytes.
	MaxText = 128
)

// Entity kinds.
const (
	EntitySensor       = "sensor"
	EntityBinarySensor = "binary_sensor"
	EntitySwitch       = "switch"
	EntityButton       = "button"
)

// Availability statuses.
const (
	Online  = "online"
	Offline = "offline"
)

// ErrInvalid is the error of every message the protocol refuses.
var ErrInvalid = errors.New("invalid device protocol message")

// ValidID reports whether s may be a device, entity or command id: 1 to 64
// lowercase ASCII letters, digits, '_' or '-', starting with a letter or a
// digit. An id is a topic level, so it never holds '/', '+' or '#'.
func ValidID(s string) bool {
	if s == "" || len(s) > MaxIDLength {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// validCommandName is ValidID that also allows '.' after the first
// character, as in relay.set.
func validCommandName(s string) bool {
	return ValidID(strings.ReplaceAll(s, ".", "_")) && !strings.HasPrefix(s, ".")
}

// Topic is the topic of message kind for device id.
func Topic(id, kind string) string { return Prefix + id + "/" + kind }

// InNamespace reports whether topic is in the protocol's namespace,
// hearth/v1 or anything below it.
func InNamespace(topic string) bool {
	return topic == strings.TrimSuffix(Prefix, "/") || strings.HasPrefix(topic, Prefix)
}

// SplitTopic returns the device id and kind of a protocol topic, or false if
// topic is not exactly hearth/v1/<id>/<kind> with a valid id and a known kind.
func SplitTopic(topic string) (id, kind string, ok bool) {
	rest, found := strings.CutPrefix(topic, Prefix)
	if !found {
		return "", "", false
	}
	id, kind, found = strings.Cut(rest, "/")
	if !found || !ValidID(id) {
		return "", "", false
	}
	switch kind {
	case KindAnnounce, KindState, KindTelemetry, KindAvailability, KindResult, KindCommand:
		return id, kind, true
	}
	return "", "", false
}

// DeviceWrites reports whether a device publishes messages of kind. Only the
// hub publishes commands.
func DeviceWrites(kind string) bool {
	switch kind {
	case KindAnnounce, KindState, KindTelemetry, KindAvailability, KindResult:
		return true
	}
	return false
}

// Announce tells the hub what a device is: its name, its entities and the
// commands it takes.
type Announce struct {
	V            int           `json:"v"`
	Name         string        `json:"name,omitempty"`
	Model        string        `json:"model,omitempty"`
	Manufacturer string        `json:"manufacturer,omitempty"`
	SWVersion    string        `json:"sw_version,omitempty"`
	Entities     []Entity      `json:"entities,omitempty"`
	Commands     []CommandSpec `json:"commands,omitempty"`
}

// Entity is one thing of a device the hub shows: a sensor reading, an
// on/off input, a switch or a button.
type Entity struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	Unit string `json:"unit,omitempty"`
}

// CommandSpec is a command a device takes.
type CommandSpec struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Result answers a command, by its id.
type Result struct {
	V       int    `json:"v"`
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// Command is the message the hub publishes on a device's command topic.
type Command struct {
	V       int             `json:"v"`
	ID      string          `json:"id"`
	Command string          `json:"command"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Message is one checked message from a device. Kind tells which field is
// set.
type Message struct {
	// Device is the id of the device that published it: the topic's, which
	// the broker checked is the publisher's own.
	Device string
	Kind   string
	// Announce is set for KindAnnounce.
	Announce *Announce
	// Values are a state message's entity values (bool, float64, string or
	// nil) or a telemetry message's readings (float64).
	Values map[string]any
	// Online is an availability message's status.
	Online bool
	// Result is set for KindResult.
	Result *Result
}

// Parse checks payload, published by device on its topic of kind, and
// returns it as a Message. Unknown fields are ignored, so that a later v1
// revision may add some; a message of another major version is refused.
func Parse(device, kind string, payload []byte) (Message, error) {
	m := Message{Device: device, Kind: kind}
	if len(payload) > MaxPayload {
		return m, fmt.Errorf("%w: %d bytes, more than %d", ErrInvalid, len(payload), MaxPayload)
	}
	var err error
	switch kind {
	case KindAnnounce:
		var a Announce
		if err = decode(payload, &a, &a.V); err == nil {
			err = checkAnnounce(&a)
		}
		m.Announce = &a
	case KindState:
		var s struct {
			V     int            `json:"v"`
			State map[string]any `json:"state"`
		}
		if err = decode(payload, &s, &s.V); err == nil {
			err = checkState(s.State)
		}
		m.Values = s.State
	case KindTelemetry:
		var s struct {
			V      int                `json:"v"`
			Values map[string]float64 `json:"values"`
		}
		if err = decode(payload, &s, &s.V); err == nil {
			err = checkTelemetry(s.Values)
		}
		m.Values = make(map[string]any, len(s.Values))
		for k, v := range s.Values {
			m.Values[k] = v
		}
	case KindAvailability:
		var s struct {
			V      int    `json:"v"`
			Status string `json:"status"`
		}
		if err = decode(payload, &s, &s.V); err == nil {
			switch s.Status {
			case Online:
				m.Online = true
			case Offline:
			default:
				err = fmt.Errorf("status must be %q or %q", Online, Offline)
			}
		}
	case KindResult:
		var r Result
		if err = decode(payload, &r, &r.V); err == nil {
			switch {
			case !validCommandID(r.ID):
				err = errors.New("id must be the command's id")
			case len(r.Message) > MaxText:
				err = fmt.Errorf("message longer than %d bytes", MaxText)
			}
		}
		m.Result = &r
	default:
		err = fmt.Errorf("a device does not publish %q messages", kind)
	}
	if err != nil {
		return m, fmt.Errorf("%w: %s: %w", ErrInvalid, kind, err)
	}
	return m, nil
}

// decode unmarshals one JSON object into v and checks its version.
func decode(payload []byte, v any, version *int) error {
	if err := json.Unmarshal(payload, v); err != nil {
		return errors.New("not a JSON object of the expected shape")
	}
	if *version != Version {
		return fmt.Errorf("v must be %d", Version)
	}
	return nil
}

func checkAnnounce(a *Announce) error {
	for _, s := range []string{a.Name, a.Model, a.Manufacturer, a.SWVersion} {
		if len(s) > MaxText {
			return fmt.Errorf("a name or model string is longer than %d bytes", MaxText)
		}
	}
	if len(a.Entities) > MaxEntities {
		return fmt.Errorf("more than %d entities", MaxEntities)
	}
	if len(a.Commands) > MaxCommands {
		return fmt.Errorf("more than %d commands", MaxCommands)
	}
	seen := map[string]bool{}
	for i, e := range a.Entities {
		switch {
		case !ValidID(e.ID):
			return fmt.Errorf("entities[%d]: id is not a valid id", i)
		case seen[e.ID]:
			return fmt.Errorf("entities[%d]: id is listed twice", i)
		case len(e.Name) > MaxText || len(e.Unit) > MaxText:
			return fmt.Errorf("entities[%d]: name or unit longer than %d bytes", i, MaxText)
		}
		switch e.Kind {
		case EntitySensor, EntityBinarySensor, EntitySwitch, EntityButton:
		default:
			return fmt.Errorf("entities[%d]: kind is not sensor, binary_sensor, switch or button", i)
		}
		seen[e.ID] = true
	}
	seen = map[string]bool{}
	for i, c := range a.Commands {
		switch {
		case !validCommandName(c.Name):
			return fmt.Errorf("commands[%d]: name is not a valid name", i)
		case seen[c.Name]:
			return fmt.Errorf("commands[%d]: name is listed twice", i)
		case len(c.Description) > MaxText:
			return fmt.Errorf("commands[%d]: description longer than %d bytes", i, MaxText)
		}
		seen[c.Name] = true
	}
	return nil
}

func checkState(s map[string]any) error {
	if len(s) == 0 {
		return errors.New("state must hold at least one entity value")
	}
	if len(s) > MaxValues {
		return fmt.Errorf("more than %d values", MaxValues)
	}
	for k, v := range s {
		if !ValidID(k) {
			return errors.New("a key is not a valid entity id")
		}
		switch v := v.(type) {
		case nil, bool, float64:
		case string:
			if len(v) > MaxText {
				return fmt.Errorf("a string value is longer than %d bytes", MaxText)
			}
		default:
			return errors.New("a value is not a boolean, number, string or null")
		}
	}
	return nil
}

func checkTelemetry(values map[string]float64) error {
	if len(values) == 0 {
		return errors.New("values must hold at least one reading")
	}
	if len(values) > MaxValues {
		return fmt.Errorf("more than %d values", MaxValues)
	}
	for k, v := range values {
		if !ValidID(k) {
			return errors.New("a key is not a valid id")
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return errors.New("a reading is not a finite number")
		}
	}
	return nil
}

// validCommandID reports whether s looks like an id the hub gives a command:
// 16 to 64 lowercase hex digits.
func validCommandID(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// CheckCommand checks a command the hub is about to send: a name the device
// announced is the caller's to check; here, its form and its params.
func CheckCommand(name string, params json.RawMessage) error {
	if !validCommandName(name) {
		return fmt.Errorf("%w: the command name is not a valid name", ErrInvalid)
	}
	if len(params) == 0 {
		return nil
	}
	if len(params) > MaxParams {
		return fmt.Errorf("%w: params longer than %d bytes", ErrInvalid, MaxParams)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(params, &obj); err != nil || obj == nil {
		return fmt.Errorf("%w: params must be a JSON object", ErrInvalid)
	}
	return nil
}
