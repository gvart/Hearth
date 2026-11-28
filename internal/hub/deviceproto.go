// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/deviceproto"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// The Device Protocol on the hub (docs/spec/device-protocol-v1.md). The MQTT
// broker checks each message and that its device published it on its own
// topic; DeviceProtocol turns an announce into a device of the registry,
// keeps its latest state and telemetry in the device's facts, keeps it online
// while it is connected, and sends it commands, each one a policy decision
// (device.command) and audited.

// Defaults of DeviceProtocolConfig.
const (
	DefaultProtocolCommandTimeout = 10 * time.Second
	// DefaultProtocolFlush is how often state and telemetry are written:
	// every message is not a replicated write.
	DefaultProtocolFlush = 2 * time.Second
	// DefaultProtocolSeen is how often a connected device is marked seen,
	// well within DefaultOfflineAfter.
	DefaultProtocolSeen = 10 * time.Second
	// maxProtocolQueue bounds the announces and departures waiting to be
	// written. Beyond it they are dropped, and logged.
	maxProtocolQueue = 1024
)

// Errors of DeviceProtocol.Command.
var (
	ErrProtocolDeviceNotFound = errors.New("no such device protocol device")
	ErrProtocolUnknownCommand = errors.New("the device did not announce that command")
	ErrProtocolBadCommand     = errors.New("bad command")
	ErrProtocolUnavailable    = errors.New("the device is not connected to this hub's MQTT broker")
	ErrProtocolTimeout        = errors.New("the device did not answer the command in time")
	ErrProtocolFailed         = errors.New("the device answered that the command failed")
	// ErrProtocolUserNotRemoved fails DeviceProtocol.Remove when the
	// device's MQTT user could not be removed: nothing was.
	ErrProtocolUserNotRemoved = errors.New("cannot remove the device's MQTT user")
)

// ProtocolBus is the MQTT broker as DeviceProtocol needs it (mqtt.Broker).
type ProtocolBus interface {
	// PublishCommand publishes payload on device id's command topic.
	PublishCommand(id string, payload []byte) error
	// Connected reports whether device id has a connection to the broker.
	Connected(id string) bool
	// RemoveUser removes the MQTT user of device id, from the clients file
	// and the broker, ending its connections, and reports whether there was
	// one.
	RemoveUser(id string) (bool, error)
}

// DeviceProtocolConfig holds DeviceProtocol's dependencies. Zero durations
// select the defaults.
type DeviceProtocolConfig struct {
	Store    *store.Store
	Registry *Registry
	Policy   *policy.Engine
	Log      *slog.Logger
	// Now is the clock; it defaults to time.Now.
	Now            func() time.Time
	CommandTimeout time.Duration
	Flush          time.Duration
	Seen           time.Duration
}

// DeviceProtocol is the hub's side of the Device Protocol. Its DeviceMessage
// and DeviceGone run on the broker's packet path and never block on the
// store: they queue, and Run writes.
type DeviceProtocol struct {
	devices store.Devices
	reg     *Registry
	pol     *policy.Engine
	log     *slog.Logger
	now     func() time.Time
	timeout time.Duration
	flush   time.Duration
	seen    time.Duration
	kick    chan struct{}
	// applyMu orders applyOps and Remove's forget and delete.
	applyMu sync.Mutex

	mu  sync.Mutex
	bus ProtocolBus
	// ops are the announces and departures not yet written, in order.
	ops []protocolOp
	// live are the devices that announced themselves and are connected.
	live map[string]bool
	// announced is each device's last announce, from this hub's broker.
	announced map[string]*deviceproto.Announce
	// state and telemetry are the values not yet written, by device.
	state, telemetry map[string]map[string]any
	// waiters are the commands sent, by their id, waiting for a result.
	waiters map[string]*protocolWaiter
}

type protocolOp struct {
	device   string
	announce *deviceproto.Announce // nil: the device went offline
}

type protocolWaiter struct {
	device string
	result chan deviceproto.Result
}

// ProtocolFacts is what a Device Protocol device's facts hold, under the key
// "device_protocol".
type ProtocolFacts struct {
	V            int                       `json:"v"`
	ID           string                    `json:"id"`
	Model        string                    `json:"model,omitempty"`
	Manufacturer string                    `json:"manufacturer,omitempty"`
	SWVersion    string                    `json:"sw_version,omitempty"`
	Entities     []deviceproto.Entity      `json:"entities"`
	Commands     []deviceproto.CommandSpec `json:"commands"`
	State        map[string]any            `json:"state"`
	Telemetry    map[string]any            `json:"telemetry"`
	// CommandClass is the policy class of device.command.
	CommandClass string    `json:"command_class"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type protocolFactsDoc struct {
	DeviceProtocol *ProtocolFacts `json:"device_protocol"`
}

// NewDeviceProtocol returns the hub's Device Protocol handler. Give it the
// broker with SetBus, and call Run.
func NewDeviceProtocol(cfg DeviceProtocolConfig) *DeviceProtocol {
	p := &DeviceProtocol{
		devices: cfg.Store.Devices(), reg: cfg.Registry, pol: cfg.Policy, log: cfg.Log, now: cfg.Now,
		timeout: orDefault(cfg.CommandTimeout, DefaultProtocolCommandTimeout),
		flush:   orDefault(cfg.Flush, DefaultProtocolFlush),
		seen:    orDefault(cfg.Seen, DefaultProtocolSeen),
		kick:    make(chan struct{}, 1),
		live:    map[string]bool{}, announced: map[string]*deviceproto.Announce{},
		state: map[string]map[string]any{}, telemetry: map[string]map[string]any{},
		waiters: map[string]*protocolWaiter{},
	}
	if p.log == nil {
		p.log = slog.New(slog.DiscardHandler)
	}
	if p.now == nil {
		p.now = time.Now
	}
	return p
}

// SetBus gives p the broker its devices connect to. The broker is made with
// p as its sink, so it comes after.
func (p *DeviceProtocol) SetBus(b ProtocolBus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bus = b
}

// DeviceMessage takes a checked message from the broker (mqtt.ProtocolSink).
func (p *DeviceProtocol) DeviceMessage(m deviceproto.Message) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch m.Kind {
	case deviceproto.KindAnnounce:
		p.enqueueLocked(protocolOp{device: m.Device, announce: m.Announce})
	case deviceproto.KindAvailability:
		if !m.Online {
			p.enqueueLocked(protocolOp{device: m.Device})
		}
		// Online: the device is live from its announce, which it sends on
		// every connect.
	case deviceproto.KindState:
		mergeValues(p.state, m.Device, m.Values)
	case deviceproto.KindTelemetry:
		mergeValues(p.telemetry, m.Device, m.Values)
	case deviceproto.KindResult:
		w := p.waiters[m.Result.ID]
		// A device answers only its own commands.
		if w != nil && w.device == m.Device {
			delete(p.waiters, m.Result.ID)
			w.result <- *m.Result
		}
	}
}

// DeviceGone takes the end of device id's last connection
// (mqtt.ProtocolSink).
func (p *DeviceProtocol) DeviceGone(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.live[id] || p.announced[id] != nil {
		p.enqueueLocked(protocolOp{device: id})
	}
}

func (p *DeviceProtocol) enqueueLocked(op protocolOp) {
	if len(p.ops) >= maxProtocolQueue {
		p.log.Warn("device protocol queue full, message dropped", "device", op.device)
		return
	}
	p.ops = append(p.ops, op)
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func mergeValues(into map[string]map[string]any, device string, values map[string]any) {
	m := into[device]
	if m == nil {
		m = map[string]any{}
		into[device] = m
	}
	maps.Copy(m, values)
}

// Run writes what the devices send until ctx is done.
func (p *DeviceProtocol) Run(ctx context.Context) error {
	flush := time.NewTicker(p.flush)
	defer flush.Stop()
	seen := time.NewTicker(p.seen)
	defer seen.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-p.kick:
			p.applyOps(ctx)
		case <-flush.C:
			p.applyOps(ctx)
			p.flushValues(ctx)
		case <-seen.C:
			p.markSeen(ctx)
		}
	}
}

func (p *DeviceProtocol) applyOps(ctx context.Context) {
	// A removal waits for the ops taken here to be written, so it does
	// not miss one and leave its device registered.
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	p.mu.Lock()
	ops := p.ops
	p.ops = nil
	p.mu.Unlock()
	for _, op := range ops {
		if op.announce == nil {
			p.goOffline(ctx, op.device)
			continue
		}
		if err := p.register(ctx, op.device, op.announce); err != nil {
			p.log.WarnContext(ctx, "device protocol: register device", "device", op.device, "err", err)
			continue
		}
		p.mu.Lock()
		p.announced[op.device] = op.announce
		p.live[op.device] = true
		p.mu.Unlock()
		// A device that left while its announce waited stays offline: its
		// departure may have come before the announce was written.
		if !p.connected(op.device) {
			p.goOffline(ctx, op.device)
		}
	}
}

// connected reports whether device name has a connection to the broker.
func (p *DeviceProtocol) connected(name string) bool {
	p.mu.Lock()
	bus := p.bus
	p.mu.Unlock()
	return bus != nil && bus.Connected(name)
}

// goOffline stops marking device name seen and marks it offline.
func (p *DeviceProtocol) goOffline(ctx context.Context, name string) {
	p.mu.Lock()
	delete(p.live, name)
	p.mu.Unlock()
	if err := p.reg.markDevicesOffline(ctx, []string{store.ProtocolDeviceID(name)}); err != nil {
		p.log.ErrorContext(ctx, "device protocol: mark device offline", "device", name, "err", err)
	}
}

// register adds or updates the device of an announce, online. A row under its
// id that is not a Device Protocol device's is left alone.
func (p *DeviceProtocol) register(ctx context.Context, name string, a *deviceproto.Announce) error {
	id := store.ProtocolDeviceID(name)
	return p.reg.putDevice(ctx, id, func(old *store.Device) (store.Device, error) {
		labels := map[string]string{}
		var facts ProtocolFacts
		if old != nil {
			if old.Labels[store.LabelSource] != store.SourceDeviceProtocol {
				return store.Device{}, fmt.Errorf("device %s exists and is not a device protocol device", id)
			}
			maps.Copy(labels, old.Labels)
			facts = protocolFactsOf(*old)
		}
		labels[store.LabelSource] = store.SourceDeviceProtocol
		facts = ProtocolFacts{
			V: deviceproto.Version, ID: name, Model: a.Model, Manufacturer: a.Manufacturer, SWVersion: a.SWVersion,
			Entities: emptyIfNil(a.Entities), Commands: emptyIfNil(a.Commands),
			// Values of entities the device no longer has go.
			State: keep(facts.State, entityIDs(a)), Telemetry: orEmpty(facts.Telemetry),
		}
		display := a.Name
		if display == "" {
			display = name
		}
		now := p.now()
		facts.CommandClass = commandClass()
		facts.UpdatedAt = now.UTC()
		raw, err := json.Marshal(protocolFactsDoc{DeviceProtocol: &facts})
		if err != nil {
			return store.Device{}, err
		}
		return store.Device{
			ID: id, Name: display, Hostname: name, Facts: raw, Labels: labels,
			FirstSeen: now, LastSeen: now, Status: store.StatusOnline,
		}, nil
	})
}

// flushValues writes the state and telemetry received since the last flush
// into the facts of devices this hub's broker saw announce. Values for
// entities a device did not announce are dropped.
func (p *DeviceProtocol) flushValues(ctx context.Context) {
	p.mu.Lock()
	state, telemetry := p.state, p.telemetry
	p.state, p.telemetry = map[string]map[string]any{}, map[string]map[string]any{}
	announced := maps.Clone(p.announced)
	p.mu.Unlock()
	names := slices.Sorted(maps.Keys(state))
	for n := range telemetry {
		if state[n] == nil {
			names = append(names, n)
		}
	}
	for _, name := range names {
		a := announced[name]
		if a == nil {
			continue // not announced yet: the device sends its state again
		}
		ids := entityIDs(a)
		err := p.reg.updateDevice(ctx, store.ProtocolDeviceID(name), func(d store.Device) (store.Device, bool, error) {
			if d.Labels[store.LabelSource] != store.SourceDeviceProtocol {
				return d, false, nil
			}
			facts := protocolFactsOf(d)
			facts.State = orEmpty(facts.State)
			facts.Telemetry = orEmpty(facts.Telemetry)
			for k, v := range state[name] {
				if ids[k] {
					facts.State[k] = v
				}
			}
			maps.Copy(facts.Telemetry, telemetry[name])
			facts.UpdatedAt = p.now().UTC()
			raw, err := json.Marshal(protocolFactsDoc{DeviceProtocol: &facts})
			if err != nil {
				return d, false, err
			}
			d.Facts = raw
			return d, true, nil
		})
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			p.log.ErrorContext(ctx, "device protocol: write state", "device", name, "err", err)
		}
	}
}

// markSeen keeps the connected devices online, and marks offline any whose
// departure was missed (a full queue).
func (p *DeviceProtocol) markSeen(ctx context.Context) {
	p.mu.Lock()
	live := slices.Sorted(maps.Keys(p.live))
	p.mu.Unlock()
	for _, name := range live {
		if !p.connected(name) {
			p.goOffline(ctx, name)
			continue
		}
		if err := p.reg.Heartbeat(ctx, store.ProtocolDeviceID(name), 0); err != nil && !errors.Is(err, store.ErrNotFound) {
			p.log.ErrorContext(ctx, "device protocol: mark device seen", "device", name, "err", err)
		}
	}
}

// CommandRequest is a command for a device, as the API takes it.
type CommandRequest struct {
	Command string          `json:"command"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// CommandResult is a device's answer to a command.
type CommandResult struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Class   string `json:"class"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// Command sends device id the command req on behalf of actorKind/actorID and
// waits for its result. It is the policy action device.command: nothing is
// sent unless policy allows it, and the decision and outcome are audited,
// with the command's name but never its params. precheck, if not nil, is the
// policy request's Precheck (the web UI's re-authentication). The device must
// have announced the command and be connected to this hub's broker.
func (p *DeviceProtocol) Command(ctx context.Context, actorKind, actorID, id string, req CommandRequest,
	precheck func(context.Context) error,
) (CommandResult, error) {
	d, err := p.devices.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && d.Labels[store.LabelSource] != store.SourceDeviceProtocol) {
		return CommandResult{}, ErrProtocolDeviceNotFound
	}
	if err != nil {
		return CommandResult{}, err
	}
	facts := protocolFactsOf(d)
	if err := deviceproto.CheckCommand(req.Command, req.Params); err != nil {
		return CommandResult{}, fmt.Errorf("%w: %w", ErrProtocolBadCommand, err)
	}
	if !slices.ContainsFunc(facts.Commands, func(c deviceproto.CommandSpec) bool { return c.Name == req.Command }) {
		return CommandResult{}, ErrProtocolUnknownCommand
	}
	name := facts.ID
	res := CommandResult{Command: req.Command, Class: commandClass()}
	err = p.pol.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: policy.DeviceCommand, Target: d.Name + "/" + req.Command,
		Detail:   map[string]any{"device_id": id, "device": name, "command": req.Command},
		Precheck: precheck,
	}, func(ctx context.Context) error {
		r, err := p.send(ctx, name, req)
		res.ID, res.OK, res.Message = r.ID, r.OK, r.Message
		return err
	})
	if err != nil {
		return res, fmt.Errorf("%s %s: %w", req.Command, d.Name, err)
	}
	return res, nil
}

// RemoveResult is what removing a Device Protocol device did.
type RemoveResult struct {
	ID string `json:"id"`
	// MQTTUserRemoved is whether this hub's broker had the device's MQTT
	// user, now gone from its clients file. In a cluster the user may be in
	// the clients file of another hub.
	MQTTUserRemoved bool   `json:"mqtt_user_removed"`
	Class           string `json:"class"`
}

// Remove removes Device Protocol device id on behalf of actorKind/actorID:
// its MQTT user from this hub's clients file and broker, which ends its
// connections, then what the hub holds of it and its row in the registry.
// It is the policy action device.remove: nothing is changed unless policy
// allows it, and the decision and outcome are audited. precheck, if not nil,
// is the policy request's Precheck (the web UI's re-authentication).
func (p *DeviceProtocol) Remove(ctx context.Context, actorKind, actorID, id string,
	precheck func(context.Context) error,
) (RemoveResult, error) {
	d, err := p.devices.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && d.Labels[store.LabelSource] != store.SourceDeviceProtocol) {
		return RemoveResult{}, ErrProtocolDeviceNotFound
	}
	if err != nil {
		return RemoveResult{}, err
	}
	name := protocolFactsOf(d).ID
	if name == "" {
		name = d.Hostname
	}
	res := RemoveResult{ID: id, Class: removeClass()}
	err = p.pol.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: policy.DeviceRemove, Target: d.Name,
		Detail:   map[string]any{"device_id": id, "device": name},
		Precheck: precheck,
	}, func(ctx context.Context) error {
		p.mu.Lock()
		bus := p.bus
		p.mu.Unlock()
		if bus != nil {
			// First, so the device cannot announce itself again.
			removed, err := bus.RemoveUser(name)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrProtocolUserNotRemoved, err)
			}
			res.MQTTUserRemoved = removed
		}
		p.applyMu.Lock()
		defer p.applyMu.Unlock()
		p.forget(name)
		return p.reg.removeDevice(ctx, id)
	})
	if err != nil {
		return res, fmt.Errorf("remove %s: %w", d.Name, err)
	}
	return res, nil
}

// forget drops what p holds of device name: its queued announces and
// departures, presence, last announce and unwritten values.
func (p *DeviceProtocol) forget(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ops = slices.DeleteFunc(p.ops, func(op protocolOp) bool { return op.device == name })
	delete(p.live, name)
	delete(p.announced, name)
	delete(p.state, name)
	delete(p.telemetry, name)
}

func removeClass() string {
	class, _ := policy.ClassOf(policy.DeviceRemove)
	return string(class)
}

// send publishes req to device name and waits for its result.
func (p *DeviceProtocol) send(ctx context.Context, name string, req CommandRequest) (deviceproto.Result, error) {
	var b [16]byte
	_, _ = rand.Read(b[:])
	cmdID := hex.EncodeToString(b[:])
	payload, err := json.Marshal(deviceproto.Command{V: deviceproto.Version, ID: cmdID, Command: req.Command, Params: req.Params})
	if err != nil {
		return deviceproto.Result{}, err
	}
	w := &protocolWaiter{device: name, result: make(chan deviceproto.Result, 1)}
	p.mu.Lock()
	bus := p.bus
	// An approval can be minutes old: the device may have gone since.
	if bus == nil || !bus.Connected(name) {
		p.mu.Unlock()
		return deviceproto.Result{ID: cmdID}, ErrProtocolUnavailable
	}
	p.waiters[cmdID] = w
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiters, cmdID)
		p.mu.Unlock()
	}()
	if err := bus.PublishCommand(name, payload); err != nil {
		return deviceproto.Result{ID: cmdID}, fmt.Errorf("publish command: %w", err)
	}
	t := time.NewTimer(p.timeout)
	defer t.Stop()
	select {
	case r := <-w.result:
		if !r.OK {
			return r, fmt.Errorf("%w: %s", ErrProtocolFailed, r.Message)
		}
		return r, nil
	case <-t.C:
		return deviceproto.Result{ID: cmdID}, ErrProtocolTimeout
	case <-ctx.Done():
		return deviceproto.Result{ID: cmdID}, ctx.Err()
	}
}

func commandClass() string {
	class, _ := policy.ClassOf(policy.DeviceCommand)
	return string(class)
}

func protocolFactsOf(d store.Device) ProtocolFacts {
	var doc protocolFactsDoc
	if json.Unmarshal(d.Facts, &doc) != nil || doc.DeviceProtocol == nil {
		return ProtocolFacts{}
	}
	return *doc.DeviceProtocol
}

func entityIDs(a *deviceproto.Announce) map[string]bool {
	ids := map[string]bool{}
	for _, e := range a.Entities {
		if e.Kind != deviceproto.EntityButton {
			ids[e.ID] = true
		}
	}
	return ids
}

func keep(m map[string]any, ids map[string]bool) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if ids[k] {
			out[k] = v
		}
	}
	return out
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func emptyIfNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// putDevice writes the device update makes of the row under id (nil if
// there is none) and publishes device.online, or device.updated if it was
// online already.
func (r *Registry) putDevice(ctx context.Context, id string, update func(old *store.Device) (store.Device, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var old *store.Device
	switch d, err := r.devices.Get(ctx, id); {
	case err == nil:
		old = &d
	case !errors.Is(err, store.ErrNotFound):
		return err
	}
	d, err := update(old)
	if err != nil {
		return err
	}
	if err := r.devices.Upsert(ctx, d); err != nil {
		return err
	}
	if d, err = r.devices.Get(ctx, id); err != nil {
		return err
	}
	typ := EventDeviceUpdated
	if old == nil || old.Status != store.StatusOnline {
		typ = EventDeviceOnline
	}
	r.publish(ctx, Event{Type: typ, Device: d})
	return nil
}

// updateDevice writes what update makes of device id, keeping its presence,
// and publishes device.updated, unless update reports no change.
func (r *Registry) updateDevice(ctx context.Context, id string, update func(store.Device) (store.Device, bool, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, err := r.devices.Get(ctx, id)
	if err != nil {
		return err
	}
	d, changed, err := update(d)
	if err != nil || !changed {
		return err
	}
	if err := r.devices.Upsert(ctx, d); err != nil {
		return err
	}
	r.publish(ctx, Event{Type: EventDeviceUpdated, Device: d})
	return nil
}

// removeDevice deletes device id. It publishes no event: the UI refetches
// its devices, as it does for a device removed on another member.
func (r *Registry) removeDevice(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.devices.Remove(ctx, id)
}

// markDevicesOffline marks devices ids offline and publishes device.offline
// for each that was online.
func (r *Registry) markDevicesOffline(ctx context.Context, ids []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed, err := r.devices.MarkDevicesOffline(ctx, ids)
	if err != nil {
		return err
	}
	for _, d := range changed {
		r.publish(ctx, Event{Type: EventDeviceOffline, Device: d})
	}
	return nil
}
