// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// telemetrySchema is the schema version whose migration (00021) added the
// telemetry table. Before it the admin has not answered, and cannot until
// `hearth cluster migrate`.
const telemetrySchema = 21

// TelemetrySetting is the admin's answer to the telemetry prompt.
type TelemetrySetting struct {
	// Answered is false until the admin answers; Enabled is then false.
	Answered bool
	Enabled  bool
	// InstallID is random, made on opt-in; empty while telemetry is off.
	InstallID string
	// LastSent is the last attempt to send; zero for never.
	LastSent time.Time
}

// SetTelemetry stores the admin's answer. It resets the last send, so a new
// opt-in sends shortly after.
type SetTelemetry struct {
	Enabled   bool   `json:"enabled"`
	InstallID string `json:"install_id"`
	At        int64  `json:"at"`
}

// Op implements Command.
func (SetTelemetry) Op() string { return "set_telemetry" }

func (SetTelemetry) minSchema() int64 { return telemetrySchema }

func (c SetTelemetry) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO telemetry (id, enabled, install_id, answered_at, last_sent_at) VALUES (1, ?, ?, ?, 0)
		ON CONFLICT (id) DO UPDATE SET
			enabled = excluded.enabled, install_id = excluded.install_id,
			answered_at = excluded.answered_at, last_sent_at = 0`,
		c.Enabled, c.InstallID, c.At)
	return Result{}, err
}

// MarkTelemetrySent records an attempt to send for InstallID. It fails with
// ErrNotFound if telemetry was turned off, or on again with a new ID, since.
type MarkTelemetrySent struct {
	InstallID string `json:"install_id"`
	At        int64  `json:"at"`
}

// Op implements Command.
func (MarkTelemetrySent) Op() string { return "mark_telemetry_sent" }

func (MarkTelemetrySent) minSchema() int64 { return telemetrySchema }

func (c MarkTelemetrySent) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	res, err := tx.ExecContext(ctx,
		`UPDATE telemetry SET last_sent_at = ? WHERE id = 1 AND enabled = 1 AND install_id = ?`, c.At, c.InstallID)
	if err != nil {
		return Result{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Result{}, err
	}
	if n == 0 {
		return Result{}, ErrNotFound
	}
	return Result{Count: int(n)}, nil
}

// Telemetry is the repository for the telemetry setting.
type Telemetry struct{ s *Store }

// Telemetry returns the telemetry repository.
func (s *Store) Telemetry() Telemetry { return Telemetry{s: s} }

// requireSchema refuses a write before the schema that added the table. It
// runs before the proposal: a hub still on an older binary halts on a command
// it cannot decode.
func (r Telemetry) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < telemetrySchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; run `hearth cluster migrate` first",
			ErrSchemaTooOld, telemetrySchema, v)
	}
	return nil
}

// Get returns the setting. Before schema 21 the admin has not answered.
func (r Telemetry) Get(ctx context.Context) (TelemetrySetting, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return TelemetrySetting{}, fmt.Errorf("get telemetry: %w", err)
	}
	if v < telemetrySchema {
		return TelemetrySetting{}, nil
	}
	var (
		out      TelemetrySetting
		lastSent int64
	)
	err = r.s.db.QueryRowContext(ctx,
		`SELECT enabled, install_id, last_sent_at FROM telemetry WHERE id = 1`).Scan(&out.Enabled, &out.InstallID, &lastSent)
	if errors.Is(err, sql.ErrNoRows) {
		return TelemetrySetting{}, nil
	}
	if err != nil {
		return TelemetrySetting{}, fmt.Errorf("get telemetry: %w", err)
	}
	out.Answered = true
	if lastSent > 0 {
		out.LastSent = fromMillis(lastSent)
	}
	return out, nil
}

// Set stores the admin's answer: enabled with installID, or off with none.
// Before schema 21 it fails with ErrSchemaTooOld.
func (r Telemetry) Set(ctx context.Context, enabled bool, installID string, at time.Time) error {
	if enabled != (installID != "") {
		return errors.New("set telemetry: an install ID is required when on, and none when off")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("set telemetry: %w", err)
	}
	if _, err := r.s.apply(ctx, SetTelemetry{Enabled: enabled, InstallID: installID, At: toMillis(at)}); err != nil {
		return fmt.Errorf("set telemetry: %w", err)
	}
	return nil
}

// MarkSent records an attempt to send for installID at at. It fails with
// ErrNotFound if the setting changed since, and before schema 21 with
// ErrSchemaTooOld.
func (r Telemetry) MarkSent(ctx context.Context, installID string, at time.Time) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("mark telemetry sent: %w", err)
	}
	if _, err := r.s.apply(ctx, MarkTelemetrySent{InstallID: installID, At: toMillis(at)}); err != nil {
		return fmt.Errorf("mark telemetry sent: %w", err)
	}
	return nil
}

// TelemetryCounts are the only counts telemetry reads: no names, no addresses.
type TelemetryCounts struct {
	Devices        int
	KubeClusters   int
	ProxmoxServers int
}

// Counts counts devices, adopted Kubernetes clusters and Proxmox servers. It
// needs schema 21, which an enabled setting implies.
func (r Telemetry) Counts(ctx context.Context) (TelemetryCounts, error) {
	var c TelemetryCounts
	if err := r.s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM devices),
		(SELECT COUNT(*) FROM kube_clusters),
		(SELECT COUNT(*) FROM proxmox_servers)`).Scan(&c.Devices, &c.KubeClusters, &c.ProxmoxServers); err != nil {
		return TelemetryCounts{}, fmt.Errorf("count for telemetry: %w", err)
	}
	return c, nil
}
