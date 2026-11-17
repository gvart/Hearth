// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrCertRevoked is returned by Certs.Check for a revoked certificate.
var ErrCertRevoked = errors.New("certificate revoked")

// Certs is the repository for client certificates issued to devices.
type Certs struct{ s *Store }

// Certs returns the certificate repository.
func (s *Store) Certs() Certs { return Certs{s: s} }

// Create records a certificate issued to deviceID. The device must already exist.
func (r Certs) Create(ctx context.Context, serial, deviceID string) error {
	if serial == "" || deviceID == "" {
		return errors.New("create cert: serial and device ID are required")
	}
	if _, err := r.s.apply(ctx, CreateCert{Serial: serial, DeviceID: deviceID}); err != nil {
		return fmt.Errorf("create cert %s for %s: %w", serial, deviceID, err)
	}
	return nil
}

// RevokeDevice revokes every not-yet-revoked certificate of deviceID at now and
// returns how many were revoked. It returns ErrNotFound if the device has no
// certificates at all; revoking an already revoked device is a no-op.
func (r Certs) RevokeDevice(ctx context.Context, deviceID string, now time.Time) (int, error) {
	res, err := r.s.apply(ctx, RevokeDevice{DeviceID: deviceID, Now: toMillis(now)})
	if err != nil {
		return 0, fmt.Errorf("revoke device %s: %w", deviceID, err)
	}
	return res.Count, nil
}

// Check reports whether the certificate with serial may be used by deviceID.
// It returns ErrNotFound if the hub never issued it to that device and
// ErrCertRevoked if it was revoked.
func (r Certs) Check(ctx context.Context, serial, deviceID string) error {
	var revokedAt sql.NullInt64
	err := r.s.db.QueryRowContext(ctx,
		`SELECT revoked_at FROM certs WHERE serial = ? AND device_id = ?`, serial, deviceID).Scan(&revokedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("check cert %s: %w", serial, ErrNotFound)
	case err != nil:
		return fmt.Errorf("check cert %s: %w", serial, err)
	case revokedAt.Valid:
		return fmt.Errorf("check cert %s: %w", serial, ErrCertRevoked)
	}
	return nil
}
