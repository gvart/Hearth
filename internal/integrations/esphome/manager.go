// SPDX-License-Identifier: AGPL-3.0-only

// Package esphome adopts ESPHome devices through their native API: a framed
// protobuf over TCP 6053, encrypted with Noise (the device's API encryption
// key) or, on older setups, in plaintext. The hub reads each device's
// sensors, binary sensors, switches, buttons and text sensors, keeps their
// states live through the API's subscription, and turns a switch on or off
// or presses a button only through policy (esphome.call), and only on a
// device adopted with calls allowed.
package esphome

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// SealInfo names the key that seals connections: it is theirs alone.
const SealInfo = "hearth esphome connection seal v1"

// Device states.
const (
	StateConnecting  = "connecting"
	StateConnected   = "connected"
	StateUnavailable = "unavailable"
)

// Calls of Call.
const (
	ActionOn    = "on"
	ActionOff   = "off"
	ActionPress = "press"
)

const (
	// DefaultSyncInterval is how often the manager rereads the device list
	// from the store, which picks up devices added or removed through another
	// hub of the cluster.
	DefaultSyncInterval = 5 * time.Second
	// minRetry and maxRetry bound the wait before connecting again; a
	// rejected key or password waits the longest at once.
	minRetry      = time.Second
	maxRetry      = time.Minute
	maxNameLength = 63
)

// Errors of the manager's API.
var (
	ErrNotFound       = errors.New("no such esphome device")
	ErrNameTaken      = errors.New("an esphome device with that name exists")
	ErrBadName        = errors.New("device name must be 1 to 63 printable characters")
	ErrBadAction      = errors.New("invalid call: want on or off for a switch, press for a button")
	ErrEntityNotFound = errors.New("no such entity on this device")
	// ErrUnavailable is returned for a call to a device the hub is not
	// connected to at the moment.
	ErrUnavailable = errors.New("the esphome device is unavailable")
	// ErrReadOnly is returned for a call to a device adopted without calls
	// allowed. It is a policy denial, and audited as one.
	ErrReadOnly = fmt.Errorf("the device was adopted read-only: %w", policy.ErrDenied)
)

// DeviceInfo describes an adopted device and its connection. It never holds
// the key or the password.
type DeviceInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Address is the IP and port the hub connects to.
	Address string `json:"address"`
	// Encryption is noise or plaintext.
	Encryption string `json:"encryption"`
	// Control says whether switch and button calls are allowed.
	Control   bool      `json:"control"`
	State     string    `json:"state"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	// What the device said of itself on the last connection.
	DeviceName   string `json:"device_name"`
	FriendlyName string `json:"friendly_name"`
	MAC          string `json:"mac"`
	Version      string `json:"esphome_version"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
	Entities     int    `json:"entities"`
}

// Snapshot is the current state of one device.
type Snapshot struct {
	Device   DeviceInfo `json:"device"`
	Entities []Entity   `json:"entities"`
	// CallClass is the policy class of esphome.call.
	CallClass string `json:"call_class"`
}

// AddRequest adopts a device.
type AddRequest struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	// Key is the device's API encryption key, as in its YAML.
	Key string `json:"key"`
	// Password is the legacy API password of a plaintext device.
	Password string `json:"password"`
	// Control allows switch and button calls.
	Control bool `json:"control"`
}

// CallRequest is a call on one entity.
type CallRequest struct {
	Key    uint32 `json:"key"`
	Action string `json:"action"`
}

// CallResult says what was sent. The device's answer shows in the entity's
// state.
type CallResult struct {
	Action string `json:"action"`
	Class  string `json:"class"`
	Target string `json:"target"`
	Result string `json:"result"`
}

// Config holds the manager's dependencies.
type Config struct {
	Store  *store.Store
	Sealer *kubernetes.Sealer
	Policy *policy.Engine
	Log    *slog.Logger
	// SyncInterval defaults to DefaultSyncInterval.
	SyncInterval time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
	// dial is for tests.
	dial dialOptions
	// retry overrides minRetry, for tests.
	retry time.Duration
}

// Manager adopts ESPHome devices. It keeps one connection per device stored
// in the hub, serves their entities and carries out calls (see Call).
//
// Every master of the cluster connects to every device itself: the states
// are a cache of the devices, never written to the store.
type Manager struct {
	store  *store.Store
	sealer *kubernetes.Sealer
	policy *policy.Engine
	log    *slog.Logger
	every  time.Duration
	now    func() time.Time
	kick   chan struct{}
	dial   dialOptions
	retry  time.Duration

	mu      sync.Mutex
	devices map[string]*running
}

// running is one device the manager reads. Its fields after cancel are
// guarded by the manager's mu.
type running struct {
	info   DeviceInfo // ID, Name, Address, Encryption, Control, CreatedAt
	conn   Connection
	cancel context.CancelFunc
	done   chan struct{}

	state    string
	err      string
	session  *session
	entities []Entity
	index    map[uint32]int
	device   deviceInfo
}

// NewManager returns a manager. Call Run to start reading devices; nothing
// connects before that.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		store: cfg.Store, sealer: cfg.Sealer, policy: cfg.Policy, log: cfg.Log,
		every: cfg.SyncInterval, now: cfg.Now, kick: make(chan struct{}, 1),
		devices: map[string]*running{}, dial: cfg.dial, retry: cfg.retry,
	}
	if m.every <= 0 {
		m.every = DefaultSyncInterval
	}
	if m.retry <= 0 {
		m.retry = minRetry
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	return m
}

// Run reads every stored device until ctx is done, rereading the list every
// SyncInterval and at once after a local Add or Remove. A device that cannot
// be reached shows as unavailable; it never ends Run.
func (m *Manager) Run(ctx context.Context) error {
	t := time.NewTicker(m.every)
	defer t.Stop()
	defer m.stopAll()
	for {
		m.sync(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-m.kick:
		}
	}
}

func (m *Manager) sync(ctx context.Context) {
	stored, err := m.store.ESPHomeDevices().List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.ErrorContext(ctx, "list esphome devices", "err", err)
		}
		return
	}
	want := map[string]store.ESPHomeDevice{}
	for _, d := range stored {
		want[d.ID] = d
	}
	m.mu.Lock()
	var stop []*running
	for id, r := range m.devices {
		if _, ok := want[id]; !ok {
			stop = append(stop, r)
			delete(m.devices, id)
		}
	}
	for id, d := range want {
		if _, ok := m.devices[id]; !ok {
			m.devices[id] = m.start(ctx, d)
		}
	}
	m.mu.Unlock()
	for _, r := range stop {
		r.cancel()
		<-r.done
		m.log.InfoContext(ctx, "stopped reading esphome device", "device", r.info.Name)
	}
}

// start begins reading d. mu is held.
func (m *Manager) start(ctx context.Context, d store.ESPHomeDevice) *running {
	r := &running{
		info:  DeviceInfo{ID: d.ID, Name: d.Name, CreatedAt: d.CreatedAt},
		state: StateConnecting,
		done:  make(chan struct{}),
	}
	ctx, r.cancel = context.WithCancel(ctx)
	fail := func(msg string, err error) *running {
		m.log.ErrorContext(ctx, msg, "device", d.Name, "err", err)
		r.state, r.err = StateUnavailable, msg
		close(r.done)
		return r
	}
	raw, err := m.sealer.Open(d.ID, d.Sealed)
	if err != nil {
		return fail("cannot decrypt the connection", err)
	}
	var conn Connection
	if err := json.Unmarshal(raw, &conn); err != nil {
		// The error of a failed decode could quote the plaintext.
		return fail("invalid stored connection", errors.New("undecodable"))
	}
	r.conn = conn
	r.info.Address, r.info.Encryption, r.info.Control = conn.Address, conn.encryption(), conn.Control
	go func() {
		defer close(r.done)
		m.connectLoop(ctx, r)
	}()
	m.log.InfoContext(ctx, "reading esphome device", "device", d.Name, "address", conn.Address,
		"encryption", conn.encryption())
	return r
}

// connectLoop keeps a session with r's device until ctx is done, connecting
// again after a wait that doubles on each failure.
func (m *Manager) connectLoop(ctx context.Context, r *running) {
	wait := m.retry
	for {
		err := m.readOnce(ctx, r)
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		if r.err != err.Error() {
			m.log.WarnContext(ctx, "esphome device unavailable", "device", r.info.Name, "err", err)
		}
		// What was read before may no longer be true: show none of it.
		r.state, r.err, r.session, r.entities, r.index = StateUnavailable, err.Error(), nil, nil, nil
		m.mu.Unlock()
		if errors.Is(err, ErrInvalidKey) || errors.Is(err, ErrInvalidPassword) ||
			errors.Is(err, ErrNeedsKey) || errors.Is(err, ErrNotEncrypted) {
			// Trying the same key again soon changes nothing, and each try
			// costs the device a handshake.
			wait = maxRetry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, maxRetry)
	}
}

// readOnce connects once and reads the device until the connection ends.
func (m *Manager) readOnce(ctx context.Context, r *running) error {
	s, err := dial(ctx, r.conn, m.dial)
	if err != nil {
		return err
	}
	defer s.close()
	index := make(map[uint32]int, len(s.entities))
	for i, e := range s.entities {
		index[e.Key] = i
	}
	m.mu.Lock()
	r.state, r.err, r.session, r.device = StateConnected, "", s, s.info
	r.entities, r.index = s.entities, index
	m.mu.Unlock()
	m.log.InfoContext(ctx, "esphome device connected", "device", r.info.Name, "entities", len(s.entities))
	err = s.run(ctx, func(u stateUpdate) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if i, ok := r.index[u.key]; ok && r.session == s && r.entities[i].Kind != KindButton {
			r.entities[i].State = u.state
		}
	})
	if err == nil {
		err = ErrClosed
	}
	return err
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	all := m.devices
	m.devices = map[string]*running{}
	m.mu.Unlock()
	for _, r := range all {
		r.cancel()
		<-r.done
	}
}

// infoLocked fills r's state and what the device said. mu is held.
func infoLocked(r *running) DeviceInfo {
	info := r.info
	info.State, info.Error = r.state, r.err
	info.DeviceName, info.FriendlyName, info.MAC = r.device.Name, r.device.FriendlyName, r.device.MAC
	info.Version, info.Model, info.Manufacturer = r.device.Version, r.device.Model, r.device.Manufacturer
	info.Entities = len(r.entities)
	return info
}

// Devices lists the devices this hub reads, by name.
func (m *Manager) Devices() []DeviceInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DeviceInfo, 0, len(m.devices))
	for _, r := range m.devices {
		out = append(out, infoLocked(r))
	}
	slices.SortFunc(out, func(a, b DeviceInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Snapshot returns the current state of device id.
func (m *Manager) Snapshot(id string) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.devices[id]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	s := Snapshot{Device: infoLocked(r), Entities: slices.Clone(r.entities), CallClass: callClass()}
	if s.Entities == nil {
		s.Entities = []Entity{}
	}
	return s, nil
}

func callClass() string {
	class, _ := policy.ClassOf(policy.ESPHomeCall)
	return string(class)
}

// resolve finds entity key of device id on the live session.
func (m *Manager) resolve(id string, key uint32) (*running, *session, Entity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.devices[id]
	if !ok {
		return nil, nil, Entity{}, ErrNotFound
	}
	if r.state != StateConnected || r.session == nil {
		return r, nil, Entity{}, ErrUnavailable
	}
	i, ok := r.index[key]
	if !ok {
		return r, nil, Entity{}, ErrEntityNotFound
	}
	return r, r.session, r.entities[i], nil
}

// Call turns a switch of device id on or off, or presses one of its buttons,
// on behalf of actorKind/actorID. Policy decides before anything is sent,
// and audits the decision; a device adopted read-only is refused there, as
// a denial.
func (m *Manager) Call(ctx context.Context, actorKind, actorID, id string, req CallRequest) (CallResult, error) {
	r, _, e, err := m.resolve(id, req.Key)
	if err != nil {
		return CallResult{}, err
	}
	switch {
	case e.Kind == KindSwitch && (req.Action == ActionOn || req.Action == ActionOff):
	case e.Kind == KindButton && req.Action == ActionPress:
	default:
		return CallResult{}, ErrBadAction
	}
	target := r.info.Name + "/" + e.ObjectID
	detail := map[string]any{"device_id": id, "key": e.Key, "kind": e.Kind, "action": req.Action, "name": e.Name}
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: policy.ESPHomeCall, Target: target, Detail: detail,
		Precheck: func(context.Context) error {
			if !r.info.Control {
				return ErrReadOnly
			}
			return nil
		},
	}, func(context.Context) error {
		// An approval can be minutes old: the session may have ended, or
		// the device been flashed with other entities.
		_, s, now, err := m.resolve(id, req.Key)
		if err != nil {
			return err
		}
		if now.Kind != e.Kind || now.ObjectID != e.ObjectID {
			return fmt.Errorf("%w: key %d is now %s %q", ErrEntityNotFound, req.Key, now.Kind, now.ObjectID)
		}
		if e.Kind == KindButton {
			return s.pressButton(e.Key)
		}
		return s.switchCommand(e.Key, req.Action == ActionOn)
	})
	if err != nil {
		return CallResult{}, fmt.Errorf("%s %s: %w", req.Action, target, err)
	}
	return CallResult{
		Action: req.Action, Class: callClass(), Target: target,
		Result: fmt.Sprintf("sent %s to %s", req.Action, target),
	}, nil
}

// Add adopts a device on behalf of a web session from actorID, without
// connecting to it: one that cannot be reached yet shows as unavailable. The
// connection is sealed before it is stored. It is a policy action, audited;
// the key is never in the audit entry.
func (m *Manager) Add(ctx context.Context, actorID string, req AddRequest) (DeviceInfo, error) {
	name := strings.TrimSpace(req.Name)
	if !validName(name) {
		return DeviceInfo{}, ErrBadName
	}
	conn, err := Connection{Address: req.Address, Key: req.Key, Password: req.Password, Control: req.Control}.normalize()
	if err != nil {
		return DeviceInfo{}, err
	}
	// The id is derived from the name, so two hubs adding the same name
	// make one device.
	id := store.ESPHomeDeviceID(name)
	now := m.now().UTC().Truncate(time.Millisecond)
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.ESPHomeDeviceAdd, Target: name,
		Detail: map[string]any{"id": id, "address": conn.Address, "encryption": conn.encryption(), "control": conn.Control},
	}, func(ctx context.Context) error {
		existing, err := m.store.ESPHomeDevices().List(ctx)
		if err != nil {
			return err
		}
		for _, d := range existing {
			if d.Name == name {
				return ErrNameTaken
			}
		}
		raw, err := json.Marshal(conn) //nolint:gosec // sealed before it is stored
		if err != nil {
			return errors.New("encode connection")
		}
		sealed, err := m.sealer.Seal(id, raw)
		if err != nil {
			return err
		}
		return m.store.ESPHomeDevices().Add(ctx, store.ESPHomeDevice{ID: id, Name: name, Sealed: sealed, CreatedAt: now})
	})
	if err != nil {
		return DeviceInfo{}, err
	}
	m.kickSync()
	return DeviceInfo{
		ID: id, Name: name, Address: conn.Address, Encryption: conn.encryption(), Control: conn.Control,
		State: StateConnecting, CreatedAt: now,
	}, nil
}

// Remove forgets device id and its key. It is a policy action, audited.
func (m *Manager) Remove(ctx context.Context, actorID, id string) error {
	target := id
	m.mu.Lock()
	if r, ok := m.devices[id]; ok {
		target = r.info.Name
	}
	m.mu.Unlock()
	err := m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.ESPHomeDeviceRemove, Target: target,
		Detail: map[string]any{"id": id},
	}, func(ctx context.Context) error {
		return m.store.ESPHomeDevices().Remove(ctx, id)
	})
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	m.kickSync()
	return nil
}

func (m *Manager) kickSync() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func validName(s string) bool {
	if s == "" || len(s) > maxNameLength {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
