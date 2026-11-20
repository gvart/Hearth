// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Device is a machine known to the hub.
type Device struct {
	ID       string
	Name     string
	Hostname string
	OS       string
	Arch     string
	// Facts is an opaque JSON document describing the device; nil is stored as {}.
	Facts     json.RawMessage
	Labels    map[string]string
	FirstSeen time.Time
	LastSeen  time.Time
	Status    string
	// BootTime is when the device's host last booted; zero if unknown.
	BootTime time.Time
}

// Devices is the repository for the devices table.
type Devices struct{ s *Store }

// Devices returns the device repository.
func (s *Store) Devices() Devices { return Devices{s: s} }

// Upsert inserts d, or updates every field of an existing device with the same
// ID except FirstSeen, which keeps its original value.
func (r Devices) Upsert(ctx context.Context, d Device) error {
	facts := []byte(d.Facts)
	if len(facts) == 0 {
		facts = []byte("{}")
	}
	if !json.Valid(facts) {
		return fmt.Errorf("upsert device %s: facts are not valid JSON", d.ID)
	}
	labels, err := marshalLabels(d.Labels)
	if err != nil {
		return fmt.Errorf("upsert device %s: %w", d.ID, err)
	}
	_, err = r.s.apply(ctx, UpsertDevice{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, OS: d.OS, Arch: d.Arch,
		Facts: string(facts), Labels: labels,
		FirstSeen: toMillis(d.FirstSeen), LastSeen: toMillis(d.LastSeen),
		Status: d.Status, BootTime: optMillis(d.BootTime),
	})
	if err != nil {
		return fmt.Errorf("upsert device %s: %w", d.ID, err)
	}
	return nil
}

// Get returns the device with the given ID, or ErrNotFound.
func (r Devices) Get(ctx context.Context, id string) (Device, error) {
	row := r.s.queryRowKey(ctx, id, `SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, fmt.Errorf("get device %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Device{}, fmt.Errorf("get device %s: %w", id, err)
	}
	return d, nil
}

// List returns all devices ordered by ID.
func (r Devices) List(ctx context.Context) ([]Device, error) {
	rows, err := r.s.list(ctx, "", gather{table: "devices", order: byText(0)},
		`SELECT `+deviceColumns, ` FROM devices ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("list devices: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return out, nil
}

const deviceColumns = `id, name, hostname, os, arch, facts, labels, first_seen, last_seen, status, boot_time`

func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var (
		d                   Device
		facts, labels       string
		firstSeen, lastSeen int64
		bootTime            sql.NullInt64
	)
	if err := row.Scan(&d.ID, &d.Name, &d.Hostname, &d.OS, &d.Arch, &facts, &labels,
		&firstSeen, &lastSeen, &d.Status, &bootTime); err != nil {
		return Device{}, err
	}
	d.Facts = json.RawMessage(facts)
	if err := json.Unmarshal([]byte(labels), &d.Labels); err != nil {
		return Device{}, fmt.Errorf("decode labels: %w", err)
	}
	d.FirstSeen = fromMillis(firstSeen)
	d.LastSeen = fromMillis(lastSeen)
	if bootTime.Valid {
		d.BootTime = fromMillis(bootTime.Int64)
	}
	return d, nil
}

// optMillis is t in unix milliseconds, or nil if t is zero.
func optMillis(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	ms := toMillis(t)
	return &ms
}

func marshalLabels(l map[string]string) (string, error) {
	if l == nil {
		return "{}", nil
	}
	b, err := json.Marshal(l)
	if err != nil {
		return "", fmt.Errorf("encode labels: %w", err)
	}
	return string(b), nil
}
