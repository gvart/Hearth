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
// carries Host instead.
type Event struct {
	Type   string
	Device store.Device
	Host   *store.NetworkHost
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
	// Replicated selects the clustered mode: the store is replicated by Raft,
	// presence is kept by the leader only (see RunReplicated), and last_seen
	// is batched. False is a standalone hub, which writes every heartbeat.
	Replicated bool
	// SeenFlushInterval is how often a clustered leader writes the batched
	// last_seen of its devices; it defaults to DefaultSeenFlushInterval.
	SeenFlushInterval time.Duration
}

// DefaultSeenFlushInterval is how often a clustered leader flushes last_seen.
const DefaultSeenFlushInterval = 30 * time.Second

// Registry tracks device facts and presence and publishes changes as events.
// Presence lives in the store (status, last_seen); a single sweep marks silent
// devices offline, so there is no per-device timer or goroutine.
//
// In clustered mode (RegistryConfig.Replicated) only the leader tracks
// presence. Online/offline transitions, facts and boot time changes go through
// Raft at once; the last_seen of devices already online is kept in memory and
// flushed as one MarkSeenBatch about every SeenFlushInterval. The leader
// decides who is silent from that memory, and the API shows it as last_seen.
type Registry struct {
	devices      store.Devices
	log          *slog.Logger
	offlineAfter time.Duration
	now          func() time.Time
	replicated   bool
	flushEvery   time.Duration

	// mu orders each store update with its event, so subscribers never see
	// a stale status win (e.g. a sweep's offline after a newer heartbeat).
	mu  sync.Mutex
	bus bus

	// liveMu guards the clustered leader's presence memory. Reads for the API
	// take only liveMu, never mu, which is held across Raft writes.
	liveMu sync.Mutex
	// seen is the last heartbeat of each device this leader heard from; nil
	// when not leading.
	seen map[string]time.Time
	// dirty are the devices whose seen time is not stored yet.
	dirty map[string]struct{}
	// leadSince is when this hub started leading. Online devices count as
	// seen then, so a new leader gives agents one OfflineAfter to reconnect
	// instead of marking them offline on stale stored last_seen.
	leadSince time.Time

	// termMu guards term, the clustered leader's current term. It is
	// cancelled when leadership ends, which ends every agent stream.
	termMu sync.Mutex
	term   context.Context
	endT   context.CancelFunc
}

// NewRegistry returns a registry. Call Run to enable the offline sweep.
func NewRegistry(cfg RegistryConfig) *Registry {
	r := &Registry{
		devices:      cfg.Store.Devices(),
		log:          cfg.Log,
		offlineAfter: cfg.OfflineAfter,
		now:          cfg.Now,
		replicated:   cfg.Replicated,
		flushEvery:   cfg.SeenFlushInterval,
	}
	if r.flushEvery <= 0 {
		r.flushEvery = DefaultSeenFlushInterval
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
	if r.replicated {
		// The facts write stored last_seen too.
		r.liveMu.Lock()
		if r.seen != nil {
			r.seen[deviceID] = asStored(now)
			delete(r.dirty, deviceID)
		}
		r.liveMu.Unlock()
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
	d, prev, ok, err := r.markSeen(ctx, deviceID, now)
	if err != nil || !ok {
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

// markSeen records a heartbeat at now and returns the device, with last_seen
// at now, and its status before. A standalone hub writes it to the store. A
// clustered leader writes only a status change through Raft and otherwise
// keeps last_seen in memory for the next batch. A clustered hub that is not
// leading drops the heartbeat (ok false): its agent streams are ending.
func (r *Registry) markSeen(ctx context.Context, deviceID string, now time.Time) (d store.Device, prev string, ok bool, err error) {
	if !r.replicated {
		d, prev, err = r.devices.MarkSeen(ctx, deviceID, now)
		return d, prev, err == nil, err
	}
	r.liveMu.Lock()
	leading := r.seen != nil
	r.liveMu.Unlock()
	if !leading {
		return store.Device{}, "", false, nil
	}
	now = asStored(now)
	if d, err = r.devices.Get(ctx, deviceID); err != nil {
		return store.Device{}, "", false, err
	}
	prev = d.Status
	stored := prev != store.StatusOnline
	if stored {
		if d, prev, err = r.devices.MarkSeen(ctx, deviceID, now); err != nil {
			return store.Device{}, "", false, err
		}
	}
	d.LastSeen = now
	r.liveMu.Lock()
	defer r.liveMu.Unlock()
	if r.seen == nil {
		return d, prev, true, nil
	}
	r.seen[deviceID] = now
	if stored {
		delete(r.dirty, deviceID)
	} else {
		r.dirty[deviceID] = struct{}{}
	}
	return d, prev, true, nil
}

// asStored is t as the store keeps it: UTC, in milliseconds. In-memory
// last_seen values use it, so the API shows one format either way.
func asStored(t time.Time) time.Time { return time.UnixMilli(t.UnixMilli()).UTC() }

// Live returns d with the last_seen this hub holds in memory when that is
// newer than the stored one: on a clustered leader last_seen is written in
// batches, and the API shows the live value.
func (r *Registry) Live(d store.Device) store.Device {
	if !r.replicated {
		return d
	}
	r.liveMu.Lock()
	defer r.liveMu.Unlock()
	if t, ok := r.seen[d.ID]; ok && t.After(d.LastSeen) {
		d.LastSeen = t
	}
	return d
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
	var (
		devs []store.Device
		err  error
	)
	if r.replicated {
		devs, err = r.sweepLive(ctx)
	} else {
		devs, err = r.devices.MarkOffline(ctx, r.now().Add(-r.offlineAfter))
	}
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

// sweepLive is Sweep on a clustered leader: a device is silent when neither
// the store, nor this leader's memory, nor the start of its leadership is
// within OfflineAfter. The silent devices are named in one Raft write, after
// their pending last_seen is flushed. Callers hold mu.
func (r *Registry) sweepLive(ctx context.Context) ([]store.Device, error) {
	all, err := r.devices.List(ctx)
	if err != nil {
		return nil, err
	}
	cutoff := r.now().Add(-r.offlineAfter)
	var (
		silent []string
		flush  bool
	)
	r.liveMu.Lock()
	if r.seen == nil {
		r.liveMu.Unlock()
		return nil, nil
	}
	for _, d := range all {
		if d.Status != store.StatusOnline {
			continue
		}
		last := d.LastSeen
		if t, ok := r.seen[d.ID]; ok && t.After(last) {
			last = t
		}
		if r.leadSince.After(last) {
			last = r.leadSince
		}
		if last.Before(cutoff) {
			silent = append(silent, d.ID)
			_, dirty := r.dirty[d.ID]
			flush = flush || dirty
		}
	}
	r.liveMu.Unlock()
	if len(silent) == 0 {
		return nil, nil
	}
	if flush {
		if err := r.flushLocked(ctx); err != nil {
			return nil, err
		}
	}
	devs, err := r.devices.MarkDevicesOffline(ctx, silent)
	if err != nil {
		return nil, err
	}
	r.liveMu.Lock()
	for _, d := range devs {
		delete(r.seen, d.ID)
	}
	r.liveMu.Unlock()
	return devs, nil
}

// flushLocked writes the pending last_seen of every device in one
// MarkSeenBatch. On failure they stay pending for the next flush. Callers
// hold mu.
func (r *Registry) flushLocked(ctx context.Context) error {
	r.liveMu.Lock()
	batch := make(map[string]time.Time, len(r.dirty))
	for id := range r.dirty {
		batch[id] = r.seen[id]
	}
	r.liveMu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if _, err := r.devices.MarkSeenBatch(ctx, batch); err != nil {
		return err
	}
	r.liveMu.Lock()
	for id, t := range batch {
		// A heartbeat that arrived meanwhile is newer and stays pending.
		if r.seen[id].Equal(t) {
			delete(r.dirty, id)
		}
	}
	r.liveMu.Unlock()
	return nil
}

// Flush writes the pending last_seen of a clustered leader now.
func (r *Registry) Flush(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushLocked(ctx)
}

// LeaderNode is the part of a cluster node the registry's leader-only
// services need.
type LeaderNode interface {
	// IsLeader reports whether this hub is the leader now.
	IsLeader() bool
	// WaitReady blocks until this node has applied everything the cluster
	// committed before it, or ctx is done.
	WaitReady(ctx context.Context) error
}

// RunReplicated runs the clustered registry until ctx is done. While node
// leads, and once it has caught up (WaitReady), it starts a leadership term:
// it accepts agent streams, sweeps silent devices offline and flushes
// last_seen batches. When node stops leading, the term ends: every agent
// stream is closed with a NotLeader error so agents move to the new leader,
// and the pending last_seen batch is handed to the new leader. changed
// signals that leadership may have changed; RunReplicated re-checks IsLeader
// on every signal.
func (r *Registry) RunReplicated(ctx context.Context, node LeaderNode, changed <-chan struct{}) error {
	var (
		stop context.CancelFunc
		done chan struct{}
	)
	stopLeading := func() {
		if stop != nil {
			stop()
			<-done
			stop, done = nil, nil
		}
	}
	defer stopLeading()
	for {
		if !node.IsLeader() {
			stopLeading()
		} else if stop == nil {
			lctx, cancel := context.WithCancel(ctx)
			d := make(chan struct{})
			stop, done = cancel, d
			go func() {
				defer close(d)
				r.lead(lctx, node)
			}()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		}
	}
}

// lead runs one leadership term until ctx is done.
func (r *Registry) lead(ctx context.Context, node LeaderNode) {
	if err := node.WaitReady(ctx); err != nil {
		return
	}
	r.startTerm()
	r.log.InfoContext(ctx, "leading the cluster: accepting agents, sweeping presence")
	sweep := time.NewTicker(max(r.offlineAfter/6, 10*time.Millisecond))
	defer sweep.Stop()
	flush := time.NewTicker(r.flushEvery)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			r.endTerm(ctx)
			return
		case <-sweep.C:
			if err := r.Sweep(ctx); err != nil && ctx.Err() == nil {
				r.log.ErrorContext(ctx, "sweep offline devices", "err", err)
			}
		case <-flush.C:
			if err := r.Flush(ctx); err != nil && ctx.Err() == nil {
				r.log.WarnContext(ctx, "flush last_seen", "err", err)
			}
		}
	}
}

// startTerm begins a leadership term with fresh presence memory.
func (r *Registry) startTerm() {
	r.liveMu.Lock()
	r.seen, r.dirty, r.leadSince = map[string]time.Time{}, map[string]struct{}{}, r.now()
	r.liveMu.Unlock()
	r.termMu.Lock()
	r.term, r.endT = context.WithCancel(context.Background())
	r.termMu.Unlock()
}

// endTerm ends the term: agent streams close at once, then the pending
// last_seen batch is written, through the new leader if there is one.
func (r *Registry) endTerm(ctx context.Context) {
	r.termMu.Lock()
	if r.endT != nil {
		r.endT()
	}
	r.term, r.endT = nil, nil
	r.termMu.Unlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := r.flushLocked(fctx); err != nil {
		r.log.WarnContext(ctx, "last_seen of the ending term not written", "err", err)
	}
	r.liveMu.Lock()
	r.seen, r.dirty, r.leadSince = nil, nil, time.Time{}
	r.liveMu.Unlock()
	r.log.InfoContext(ctx, "no longer leading the cluster")
}

// currentTerm is the clustered leader's current term, or nil when this hub
// is not leading.
func (r *Registry) currentTerm() context.Context {
	r.termMu.Lock()
	defer r.termMu.Unlock()
	return r.term
}

func (r *Registry) publish(ctx context.Context, e Event) {
	switch e.Type {
	case EventDeviceOnline, EventDeviceOffline:
		r.log.InfoContext(ctx, e.Type, "device_id", e.Device.ID, "hostname", e.Device.Hostname)
	}
	r.bus.publish(e)
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

// active reports whether anyone is subscribed.
func (b *bus) active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs) > 0
}

// dropAll ends every subscription.
func (b *bus) dropAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		delete(b.subs, ch)
		close(ch)
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
