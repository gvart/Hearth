// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// Presence in an AP cluster (docs/design/ap-cluster.md §6). Every master
// records the heartbeats of the agents streaming to it. The master holding
// a device's stream (its route names it) owns the device's online and
// offline; a device whose route names no live master is swept by the master
// owning its id on the ring of masters, once that master has owned it for
// one offline grace period. No other master marks it offline, whatever
// last_seen its copy says.

// PresenceRing is the ring of masters as presence needs it
// (cluster.MasterRing).
type PresenceRing interface {
	Self() string
	Live(id string) bool
	Owns(key string) bool
	// Since is when the live masters last changed.
	Since() time.Time
}

// PresenceOwner returns whether this master owns the presence of a device
// in an AP cluster: it holds the device's stream, or its route names it, or
// the route names no live master and this master owns the device on ring
// and has for grace.
func PresenceOwner(agents *Agents, routes store.DeviceRoutes, ring PresenceRing, grace time.Duration,
	now func() time.Time,
) func(ctx context.Context, d store.Device) bool {
	return func(ctx context.Context, d store.Device) bool {
		if agents.Local(d.ID) {
			return true
		}
		route, err := routes.Get(ctx, d.ID)
		if err == nil {
			if route.Master == ring.Self() {
				return true
			}
			if ring.Live(route.Master) {
				return false
			}
		}
		return ring.Owns(d.ID) && now().Sub(ring.Since()) >= grace
	}
}

// SweepOwned marks offline the online devices silent for longer than the
// offline timeout whose presence owns says this hub owns, and publishes
// device.offline for each. A device seen meanwhile on its replica is spared.
func (r *Registry) SweepOwned(ctx context.Context, owns func(context.Context, store.Device) bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-r.offlineAfter)
	devs, err := r.devices.List(ctx)
	if err != nil {
		return err
	}
	var ids []string
	for _, d := range devs {
		if d.Status == store.StatusOnline && d.LastSeen.Before(cutoff) && owns(ctx, d) {
			ids = append(ids, d.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	changed, err := r.devices.MarkStaleOffline(ctx, ids, cutoff)
	if err != nil {
		return err
	}
	for _, d := range changed {
		r.publish(ctx, Event{Type: EventDeviceOffline, Device: d})
	}
	return nil
}

// RunOwned sweeps as Run does, with SweepOwned: the presence sweep of a
// master of an AP cluster.
func (r *Registry) RunOwned(ctx context.Context, owns func(context.Context, store.Device) bool) error {
	t := time.NewTicker(max(r.offlineAfter/6, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.SweepOwned(ctx, owns); err != nil && ctx.Err() == nil {
				r.log.ErrorContext(ctx, "sweep offline devices", "err", err)
			}
		}
	}
}
