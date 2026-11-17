// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	d, prev, err := r.updateOne(ctx, id,
		`hostname = ?, os = ?, arch = ?, facts = ?, last_seen = ?, status = '`+StatusOnline+`'`,
		f.Hostname, f.OS, f.Arch, string(facts), toMillis(now))
	if err != nil {
		return Device{}, "", fmt.Errorf("report facts of device %s: %w", id, err)
	}
	return d, prev, nil
}

// MarkSeen sets last_seen of device id to now and marks it online. It returns
// the updated device and its status before the update, or ErrNotFound.
func (r Devices) MarkSeen(ctx context.Context, id string, now time.Time) (Device, string, error) {
	d, prev, err := r.updateOne(ctx, id, `last_seen = ?, status = '`+StatusOnline+`'`, toMillis(now))
	if err != nil {
		return Device{}, "", fmt.Errorf("mark device %s seen: %w", id, err)
	}
	return d, prev, nil
}

// updateOne applies set to device id in one transaction and returns the
// updated row and the status it had before.
func (r Devices) updateOne(ctx context.Context, id, set string, args ...any) (d Device, prev string, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, "", err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	err = tx.QueryRowContext(ctx, `SELECT status FROM devices WHERE id = ?`, id).Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, "", ErrNotFound
	}
	if err != nil {
		return Device{}, "", err
	}
	// set is a constant from this file's callers; values are bound parameters.
	row := tx.QueryRowContext(ctx, `UPDATE devices SET `+set+` WHERE id = ? RETURNING `+deviceColumns, //nolint:gosec // see above
		append(args, id)...)
	if d, err = scanDevice(row); err != nil {
		return Device{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return Device{}, "", err
	}
	return d, prev, nil
}

// MarkOffline marks every online device last seen before cutoff as offline
// and returns the devices it changed, ordered by ID.
func (r Devices) MarkOffline(ctx context.Context, cutoff time.Time) ([]Device, error) {
	rows, err := r.db.QueryContext(ctx, `
		UPDATE devices SET status = '`+StatusOffline+`'
		WHERE status = '`+StatusOnline+`' AND last_seen < ?
		RETURNING `+deviceColumns, toMillis(cutoff))
	if err != nil {
		return nil, fmt.Errorf("mark devices offline: %w", err)
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("mark devices offline: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mark devices offline: %w", err)
	}
	slices.SortFunc(out, func(a, b Device) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
