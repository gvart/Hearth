// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CARotationSchema is the schema version whose migration (00023) added the
// certificate fingerprints and the ca_rotations table. Below it no
// fingerprint is recorded and the hub CA cannot be rotated.
const CARotationSchema = 23

// atSchema reports whether the database behind q is at schema min or newer.
func atSchema(ctx context.Context, q querier, minVersion int64) (bool, error) {
	v, err := schemaVersion(ctx, q)
	if err != nil {
		return false, err
	}
	return v >= minVersion, nil
}

// AtSchema reports whether the database is at schema version minVersion or
// newer; false when the version cannot be read.
func (s *Store) AtSchema(ctx context.Context, minVersion int64) bool {
	ok, err := atSchema(ctx, s.db, minVersion)
	return err == nil && ok
}

// CertRecord is a certificate issued to a device, with the fingerprints a
// hub CA rotation needs: the certificate's own and its CA's, each the
// lowercase hex SHA-256 of the DER encoding (pki.FingerprintHex).
type CertRecord struct {
	Serial      string
	DeviceID    string
	Fingerprint string
	CAFP        string
}

// Record records a certificate issued to a device, as Create does, with its
// fingerprints. Below schema 23 the fingerprints are left out of the command:
// a hub whose binary predates them could not decode it.
func (r Certs) Record(ctx context.Context, c CertRecord) error {
	if c.Serial == "" || c.DeviceID == "" {
		return errors.New("create cert: serial and device ID are required")
	}
	cmd := CreateCert{Serial: c.Serial, DeviceID: c.DeviceID}
	if ok, err := atSchema(ctx, r.s.db, CARotationSchema); err != nil {
		return fmt.Errorf("create cert %s for %s: %w", c.Serial, c.DeviceID, err)
	} else if ok {
		cmd.Fingerprint, cmd.CAFP = c.Fingerprint, c.CAFP
	}
	if _, err := r.s.apply(ctx, cmd); err != nil {
		return fmt.Errorf("create cert %s for %s: %w", c.Serial, c.DeviceID, err)
	}
	return nil
}

// Fingerprint returns the fingerprint recorded for the certificate with
// serial issued to deviceID: empty when none is, as for a certificate issued
// before schema 23 and not pinned since. It fails with ErrNotFound for an
// unknown certificate and with ErrSchemaTooOld below schema 23.
func (r Certs) Fingerprint(ctx context.Context, serial, deviceID string) (string, error) {
	if ok, err := atSchema(ctx, r.s.db, CARotationSchema); err != nil {
		return "", fmt.Errorf("cert fingerprint %s: %w", serial, err)
	} else if !ok {
		return "", fmt.Errorf("cert fingerprint %s: %w", serial, ErrSchemaTooOld)
	}
	var fp sql.NullString
	err := r.s.db.QueryRowContext(ctx,
		`SELECT fingerprint FROM certs WHERE serial = ? AND device_id = ?`, serial, deviceID).Scan(&fp)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("cert fingerprint %s: %w", serial, ErrNotFound)
	case err != nil:
		return "", fmt.Errorf("cert fingerprint %s: %w", serial, err)
	}
	return fp.String, nil
}

// Pin records fingerprint for the certificate with serial issued to
// deviceID, unless one is recorded already: trust on first use, for a
// certificate issued before schema 23. It reports whether it pinned it. Below
// schema 23 it fails with ErrSchemaTooOld.
func (r Certs) Pin(ctx context.Context, serial, deviceID, fingerprint string) (bool, error) {
	if serial == "" || deviceID == "" || fingerprint == "" {
		return false, errors.New("pin cert: serial, device ID and fingerprint are required")
	}
	res, err := r.s.apply(ctx, PinCert{Serial: serial, DeviceID: deviceID, Fingerprint: fingerprint})
	if err != nil {
		return false, fmt.Errorf("pin cert %s of %s: %w", serial, deviceID, err)
	}
	return res.Count > 0, nil
}

// PinCert records the fingerprint of a device certificate recorded without
// one. A certificate that has a fingerprint keeps it. Result: Count, 1 when
// it pinned the certificate and 0 otherwise.
type PinCert struct {
	Serial      string `json:"serial"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
}

// Op implements Command.
func (PinCert) Op() string { return "pin_cert" }

func (PinCert) minSchema() int64 { return CARotationSchema }

func (c PinCert) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	res, err := tx.ExecContext(ctx,
		`UPDATE certs SET fingerprint = ? WHERE serial = ? AND device_id = ? AND fingerprint IS NULL`,
		c.Fingerprint, c.Serial, c.DeviceID)
	if err != nil {
		return Result{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Result{}, err
	}
	return Result{Count: int(n)}, nil
}

// Record records a hub node certificate issued to c.NodeID, as RecordCert
// does, with its fingerprints, which it also fills in for a serial recorded
// without them. Below schema 23 the fingerprints are left out of the command:
// a hub whose binary predates them could not decode it.
func (r Hubs) Record(ctx context.Context, c HubCert) error {
	if c.Serial == "" || c.NodeID == "" {
		return errors.New("record hub cert: serial and node ID are required")
	}
	cmd := RecordHubCert{Serial: c.Serial, NodeID: c.NodeID}
	if ok, err := atSchema(ctx, r.s.db, CARotationSchema); err != nil {
		return fmt.Errorf("record hub cert %s of %s: %w", c.Serial, c.NodeID, err)
	} else if ok {
		cmd.Fingerprint, cmd.CAFP = c.Fingerprint, c.CAFP
	}
	if _, err := r.s.apply(ctx, cmd); err != nil {
		return fmt.Errorf("record hub cert %s of %s: %w", c.Serial, c.NodeID, err)
	}
	return nil
}
