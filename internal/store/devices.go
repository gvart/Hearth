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
type Devices struct{ db *sql.DB }

// Devices returns the device repository.
func (s *Store) Devices() Devices { return Devices{db: s.db} }

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
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO devices (id, name, hostname, os, arch, facts, labels, first_seen, last_seen, status, boot_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = excluded.name, hostname = excluded.hostname, os = excluded.os,
			arch = excluded.arch, facts = excluded.facts, labels = excluded.labels,
			last_seen = excluded.last_seen, status = excluded.status, boot_time = excluded.boot_time`,
		d.ID, d.Name, d.Hostname, d.OS, d.Arch, string(facts), labels,
		toMillis(d.FirstSeen), toMillis(d.LastSeen), d.Status, nullMillis(d.BootTime))
	if err != nil {
		return fmt.Errorf("upsert device %s: %w", d.ID, err)
	}
	return nil
}

// Get returns the device with the given ID, or ErrNotFound.
func (r Devices) Get(ctx context.Context, id string) (Device, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id)
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
	rows, err := r.db.QueryContext(ctx, `SELECT `+deviceColumns+` FROM devices ORDER BY id`)
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

// nullMillis is t in unix milliseconds, or NULL if t is zero.
func nullMillis(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: toMillis(t), Valid: true}
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
