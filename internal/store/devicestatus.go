// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Device statuses.
const (
	StatusUnknown = "unknown"
	StatusOnline  = "online"
	StatusOffline = "offline"
)

// DeviceFacts is what an agent reports about itself.
type DeviceFacts struct {
	Hostname string
	OS       string
	Arch     string
	// Facts is the full facts JSON document; nil is stored as {}.
	Facts json.RawMessage
}

// ReportFacts records facts reported by device id, sets last_seen to now and
// marks it online. Name and labels, set at enrollment, are left alone. It
// returns the updated device and its status before the update, or ErrNotFound.
func (r Devices) ReportFacts(ctx context.Context, id string, f DeviceFacts, now time.Time) (Device, string, error) {
	facts := []byte(f.Facts)
	if len(facts) == 0 {
		facts = []byte("{}")
	}
	if !json.Valid(facts) {
		return Device{}, "", fmt.Errorf("report facts of device %s: facts are not valid JSON", id)
	}
	res, err := r.s.apply(ctx, ReportFacts{
		ID: id, Hostname: f.Hostname, OS: f.OS, Arch: f.Arch, Facts: string(facts), Now: toMillis(now),
	})
	if err != nil {
		return Device{}, "", fmt.Errorf("report facts of device %s: %w", id, err)
	}
	return res.Device, res.PrevStatus, nil
}

// MarkSeen sets last_seen of device id to now and marks it online. It returns
// the updated device and its status before the update, or ErrNotFound.
func (r Devices) MarkSeen(ctx context.Context, id string, now time.Time) (Device, string, error) {
	res, err := r.s.apply(ctx, MarkSeen{ID: id, Now: toMillis(now)})
	if err != nil {
		return Device{}, "", fmt.Errorf("mark device %s seen: %w", id, err)
	}
	return res.Device, res.PrevStatus, nil
}

// SetBootTime sets the boot time of device id; the zero time clears it. It
// returns the updated device, or ErrNotFound.
func (r Devices) SetBootTime(ctx context.Context, id string, bootTime time.Time) (Device, error) {
	res, err := r.s.apply(ctx, SetBootTime{ID: id, BootTime: optMillis(bootTime)})
	if err != nil {
		return Device{}, fmt.Errorf("set boot time of device %s: %w", id, err)
	}
	return res.Device, nil
}

// MarkSeenBatch moves last_seen of each device in seen forward to the given
// time, in one write, without touching statuses. Unknown devices are skipped.
// It returns the number of devices updated.
func (r Devices) MarkSeenBatch(ctx context.Context, seen map[string]time.Time) (int, error) {
	cmd := MarkSeenBatch{Seen: make([]Seen, 0, len(seen))}
	for id, t := range seen {
		cmd.Seen = append(cmd.Seen, Seen{ID: id, LastSeen: toMillis(t)})
	}
	// A fixed order keeps the command, and so the log, deterministic.
	slices.SortFunc(cmd.Seen, func(a, b Seen) int { return strings.Compare(a.ID, b.ID) })
	res, err := r.s.apply(ctx, cmd)
	if err != nil {
		return 0, fmt.Errorf("mark %d devices seen: %w", len(seen), err)
	}
	return res.Count, nil
}

// MarkDevicesOffline marks the given devices offline if they are online and
// returns the devices it changed, ordered by ID.
func (r Devices) MarkDevicesOffline(ctx context.Context, ids []string) ([]Device, error) {
	ids = slices.Clone(ids)
	slices.Sort(ids)
	res, err := r.s.apply(ctx, MarkDevicesOffline{IDs: ids})
	if err != nil {
		return nil, fmt.Errorf("mark devices offline: %w", err)
	}
	return res.Devices, nil
}

// MarkStaleOffline marks the given devices offline if they are online and
// were last seen before cutoff, and returns the devices it changed, ordered
// by ID.
func (r Devices) MarkStaleOffline(ctx context.Context, ids []string, cutoff time.Time) ([]Device, error) {
	ids = slices.Clone(ids)
	slices.Sort(ids)
	res, err := r.s.apply(ctx, MarkDevicesOffline{IDs: ids, Cutoff: toMillis(cutoff)})
	if err != nil {
		return nil, fmt.Errorf("mark stale devices offline: %w", err)
	}
	return res.Devices, nil
}

// MarkOffline marks every online device last seen before cutoff as offline
// and returns the devices it changed, ordered by ID.
func (r Devices) MarkOffline(ctx context.Context, cutoff time.Time) ([]Device, error) {
	res, err := r.s.apply(ctx, MarkOffline{Cutoff: toMillis(cutoff)})
	if err != nil {
		return nil, fmt.Errorf("mark devices offline: %w", err)
	}
	return res.Devices, nil
}
