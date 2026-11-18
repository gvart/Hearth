// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/store"
)

// Applied publishes the device events of a command a clustered hub applied
// from the Raft log, so a UI on a follower sees the same live changes as one
// on the leader. It implements cluster.ApplyObserver with Restored, and the
// node calls it on its apply goroutine, in log order: it never blocks (the
// bus drops subscribers that fall behind) and never takes mu, which the
// leader holds while it waits for its own writes to apply.
//
// local entries were proposed by this hub while it led their term; their
// events came from the registry's own calls already, so they are skipped and
// the leader publishes exactly what it did before. Every other entry (all of
// them on a follower; on a new leader, those of earlier terms) is mapped to
// the events the leader published when it wrote it:
//
//   - ReportFacts, MarkSeen: device.online if the device was not online,
//     device.updated otherwise.
//   - SetBootTime: device.updated.
//   - MarkOffline, MarkDevicesOffline: device.offline for each device changed.
//   - MarkSeenBatch: device.updated for each device whose last_seen it moved,
//     so a follower's last_seen trails the leader's by at most one batch.
//   - RecordNetworkScan: network.device.new and network.device.returned for
//     each host the scan found for the first time or back.
//
// Other commands (UpsertDevice at enrollment, RevokeDevice, tokens,
// sessions) publish nothing, as on the leader.
func (r *Registry) Applied(cmd store.Command, res store.Result, local bool) {
	if local || !r.replicated || !r.bus.active() {
		return
	}
	switch c := cmd.(type) {
	case store.ReportFacts, store.MarkSeen:
		typ := EventDeviceUpdated
		if res.PrevStatus != store.StatusOnline {
			typ = EventDeviceOnline
		}
		r.bus.publish(Event{Type: typ, Device: res.Device})
	case store.SetBootTime:
		r.bus.publish(Event{Type: EventDeviceUpdated, Device: res.Device})
	case store.MarkOffline, store.MarkDevicesOffline:
		for _, d := range res.Devices {
			r.bus.publish(Event{Type: EventDeviceOffline, Device: d})
		}
	case store.MarkSeenBatch:
		if res.Count == 0 {
			return
		}
		for _, s := range c.Seen {
			// A local read of the row this entry just wrote.
			d, err := r.devices.Get(context.Background(), s.ID)
			if err != nil || d.LastSeen.UnixMilli() != s.LastSeen {
				continue // unknown device, or the batch did not move it
			}
			r.bus.publish(Event{Type: EventDeviceUpdated, Device: d})
		}
	case store.RecordNetworkScan:
		for _, h := range res.NewHosts {
			r.NetworkHost(discovery.EventNew, h)
		}
		for _, h := range res.ReturnedHosts {
			r.NetworkHost(discovery.EventReturned, h)
		}
	}
}

// Restored ends every event subscription after a Raft snapshot replaced the
// store: the events between the old state and the snapshot are unknown, so
// clients resync (the UI refetches the device list when its stream reopens).
func (r *Registry) Restored() { r.bus.dropAll() }
