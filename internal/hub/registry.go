// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// DefaultOfflineAfter is how long a device may go without a heartbeat before
// the registry marks it offline.
const DefaultOfflineAfter = 30 * time.Second

// Event types published by the registry.
const (
	EventDeviceOnline  = "device.online"
	EventDeviceOffline = "device.offline"
	EventDeviceUpdated = "device.updated"
)

// Event is a change to a device. Device is its state after the change. A
// network discovery event (discovery.EventNew, discovery.EventReturned)
// carries Hosts instead: every host of that type one scan found, as one event
// so that a large scan cannot overrun a subscriber's buffer.
type Event struct {
	Type   string
	Device store.Device
	Hosts  []store.NetworkHost
	// Scan is the end of a scan asked for over the API (EventNetworkScanDone).
	Scan *NetworkScanJSON
}

// RegistryConfig holds the registry's dependencies. Zero values of the
// optional fields select the defaults.
type RegistryConfig struct {
	Store *store.Store
	Log   *slog.Logger
	// OfflineAfter defaults to DefaultOfflineAfter.
	OfflineAfter time.Duration
	// Now is the clock; it defaults to time.Now.
	Now func() time.Time
}

// Registry tracks device facts and presence and publishes changes as events.
// Presence lives in the store (status, last_seen); a single sweep marks silent
// devices offline, so there is no per-device timer or goroutine.
type Registry struct {
	devices      store.Devices
	log          *slog.Logger
	offlineAfter time.Duration
	now          func() time.Time

	// mu orders each store update with its event, so subscribers never see
	// a stale status win (e.g. a sweep's offline after a newer heartbeat).
	mu  sync.Mutex
	bus bus
	// ui is the UI's feed (SubscribeUI): bus's events and those of device
	// rows merged from another member of an AP cluster.
	ui bus
}

// NewRegistry returns a registry. Call Run to enable the offline sweep.
func NewRegistry(cfg RegistryConfig) *Registry {
	r := &Registry{
		devices:      cfg.Store.Devices(),
		log:          cfg.Log,
		offlineAfter: cfg.OfflineAfter,
		now:          cfg.Now,
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	if r.offlineAfter <= 0 {
		r.offlineAfter = DefaultOfflineAfter
	}
	if r.now == nil {
		r.now = time.Now
	}
	return r
}

// Subscribe returns a channel of events and a function that ends the
// subscription. The channel is closed when the subscription ends, including
// when the subscriber falls too far behind; it should then resync.
func (r *Registry) Subscribe() (<-chan Event, func()) { return r.bus.subscribe() }

// SubscribeUI is Subscribe for the UI's event streams: it also carries a
// device.updated for each device row merged from another member of an AP
// cluster (Merged), so a UI on any master follows devices whose agents
// stream to another. The automation engine reads Subscribe only: a device
// trigger fires once, on the master the device's agent streams to.
func (r *Registry) SubscribeUI() (<-chan Event, func()) { return r.ui.subscribe() }

// Merged publishes on the UI's feed the device rows another member's writes
// changed here (see store.Store.ObserveMerges). A deleted device is left to
// the UI's next refetch: its events carry no removal.
func (r *Registry) Merged(rows []store.MergedRow) {
	for _, m := range rows {
		if m.Table != "devices" || m.Deleted || len(m.Key) != 1 {
			continue
		}
		id, ok := m.Key[0].(string)
		if !ok {
			continue
		}
		// The row was just merged here, so the read is local.
		d, err := r.devices.Get(context.Background(), id)
		if err != nil {
			r.log.Warn("read a merged device", "device_id", id, "err", err)
			continue
		}
		r.ui.publish(Event{Type: EventDeviceUpdated, Device: d})
	}
}

// ReportFacts records facts from a Hello (or a periodic facts message) and
// marks the device online. It publishes device.online if the device was not
// online, and device.updated otherwise.
func (r *Registry) ReportFacts(ctx context.Context, deviceID string, h *agentv1.Hello) error {
	facts, err := factsFromHello(h)
	if err != nil {
		return fmt.Errorf("report facts of device %s: %w", deviceID, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	d, prev, err := r.devices.ReportFacts(ctx, deviceID, facts, now)
	if err != nil {
		return err
	}
	typ := EventDeviceUpdated
	if prev != store.StatusOnline {
		typ = EventDeviceOnline
	}
	r.publish(ctx, Event{Type: typ, Device: d})
	return nil
}

// bootTimeJitter is how far a derived boot time may drift from the stored one
// before it is replaced. Heartbeat transit time and uptime rounding move the
// derived value by a little on every heartbeat; a reboot moves it by far more.
const bootTimeJitter = 2 * time.Second

// Heartbeat records that the device is alive and, if uptime is positive,
// derives its boot time as receive time minus uptime. It publishes
// device.online if the device was not online, and device.updated if it was
// and its boot time changed (first report or reboot). Otherwise it is silent.
func (r *Registry) Heartbeat(ctx context.Context, deviceID string, uptime time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	d, prev, err := r.devices.MarkSeen(ctx, deviceID, now)
	if err != nil {
		return err
	}
	changed := false
	if boot := now.Add(-uptime); uptime > 0 && (d.BootTime.IsZero() || absDuration(boot.Sub(d.BootTime)) > bootTimeJitter) {
		// On failure the presence change is still published below.
		var updated store.Device
		if updated, err = r.devices.SetBootTime(ctx, deviceID, boot); err == nil {
			d, changed = updated, true
		}
	}
	switch {
	case prev != store.StatusOnline:
		r.publish(ctx, Event{Type: EventDeviceOnline, Device: d})
	case changed:
		r.publish(ctx, Event{Type: EventDeviceUpdated, Device: d})
	}
	return err
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Sweep marks every online device not seen for OfflineAfter as offline and
// publishes device.offline for each.
func (r *Registry) Sweep(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	devs, err := r.devices.MarkOffline(ctx, r.now().Add(-r.offlineAfter))
	if err != nil {
		return err
	}
	for _, d := range devs {
		r.publish(ctx, Event{Type: EventDeviceOffline, Device: d})
	}
	return nil
}

// Run sweeps on one ticker until ctx is done. A device therefore goes offline
// between OfflineAfter and OfflineAfter plus one sweep interval after its last
// heartbeat.
func (r *Registry) Run(ctx context.Context) error {
	t := time.NewTicker(max(r.offlineAfter/6, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.Sweep(ctx); err != nil && ctx.Err() == nil {
				r.log.ErrorContext(ctx, "sweep offline devices", "err", err)
			}
		}
	}
}

func (r *Registry) publish(ctx context.Context, e Event) {
	switch e.Type {
	case EventDeviceOnline, EventDeviceOffline:
		r.log.InfoContext(ctx, e.Type, "device_id", e.Device.ID, "hostname", e.Device.Hostname)
	}
	r.fanout(e)
}

// fanout publishes e to the registry's subscribers and the UI's feed.
func (r *Registry) fanout(e Event) {
	r.bus.publish(e)
	r.ui.publish(e)
}

// subscriberBuffer is how many events a subscriber may lag behind before it
// is dropped.
const subscriberBuffer = 64

// bus is a tiny in-process fan-out. Publishing never blocks: a subscriber
// whose buffer is full is dropped (its channel closed) instead.
type bus struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func (b *bus) subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subscriberBuffer)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = make(map[chan Event]struct{})
	}
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() { b.drop(ch) }
}

func (b *bus) publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			delete(b.subs, ch)
			close(ch)
		}
	}
}

func (b *bus) drop(ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
}
