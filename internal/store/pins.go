// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CertPinsSchema is the schema version whose migration (cert_pins) added the
// certificate fingerprints. Below it no fingerprint is recorded and no
// device certificate is pinned.
const CertPinsSchema = 24

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
// fingerprints. Below CertPinsSchema the fingerprints are left out of the command:
// a hub whose binary predates them could not decode it.
func (r Certs) Record(ctx context.Context, c CertRecord) error {
	if c.Serial == "" || c.DeviceID == "" {
		return errors.New("create cert: serial and device ID are required")
	}
	cmd := CreateCert{Serial: c.Serial, DeviceID: c.DeviceID}
	if ok, err := atSchema(ctx, r.s.db, CertPinsSchema); err != nil {
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
// before CertPinsSchema and not pinned since. It fails with ErrNotFound for an
// unknown certificate and with ErrSchemaTooOld below CertPinsSchema.
func (r Certs) Fingerprint(ctx context.Context, serial, deviceID string) (string, error) {
	if ok, err := atSchema(ctx, r.s.db, CertPinsSchema); err != nil {
		return "", fmt.Errorf("cert fingerprint %s: %w", serial, err)
	} else if !ok {
		return "", fmt.Errorf("cert fingerprint %s: %w", serial, ErrSchemaTooOld)
	}
	var fp sql.NullString
	err := r.s.queryRowKey(ctx, deviceID,
		`SELECT fingerprint FROM certs WHERE serial = ? AND device_id = ?`, serial, deviceID).Scan(&fp)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("cert fingerprint %s: %w", serial, ErrNotFound)
	case err != nil:
		return "", fmt.Errorf("cert fingerprint %s: %w", serial, err)
	}
	return fp.String, nil
}

// PinOutcome is what Certs.Pin did.
type PinOutcome int

// Pin outcomes.
const (
	// PinKept: the presented certificate is the one recorded, or another
	// one whose mismatch was recorded already.
	PinKept PinOutcome = iota
	// Pinned: the certificate had no fingerprint and now has this one.
	Pinned
	// PinMismatch: the certificate has another fingerprint, and the
	// mismatch was recorded now, the first time it was seen.
	PinMismatch
)

// Pin records fingerprint and caFP, the fingerprint of the CA that issued it,
// for the certificate with serial issued to deviceID, unless a fingerprint is
// recorded already: trust on first use, for a certificate issued before
// CertPinsSchema. A recorded fingerprint that differs is a certificate someone
// minted with the CA key: the first such sighting is recorded with its time,
// now. It fails with ErrNotFound for an unknown certificate and with
// ErrSchemaTooOld below CertPinsSchema, before proposing anything.
func (r Certs) Pin(ctx context.Context, serial, deviceID, fingerprint, caFP string, now time.Time) (PinOutcome, error) {
	if serial == "" || deviceID == "" || fingerprint == "" {
		return PinKept, errors.New("pin cert: serial, device ID and fingerprint are required")
	}
	if ok, err := atSchema(ctx, r.s.db, CertPinsSchema); err != nil {
		return PinKept, fmt.Errorf("pin cert %s of %s: %w", serial, deviceID, err)
	} else if !ok {
		return PinKept, fmt.Errorf("pin cert %s of %s: %w", serial, deviceID, ErrSchemaTooOld)
	}
	res, err := r.s.apply(ctx, PinCert{Serial: serial, DeviceID: deviceID, Fingerprint: fingerprint, CAFP: caFP, Now: toMillis(now)})
	if err != nil {
		return PinKept, fmt.Errorf("pin cert %s of %s: %w", serial, deviceID, err)
	}
	switch {
	case res.Count > 0:
		return Pinned, nil
	case res.PinMismatch:
		return PinMismatch, nil
	}
	return PinKept, nil
}

// PinMismatches returns the serials of device deviceID's certificates whose
// mismatch was recorded (see Pin); none below CertPinsSchema.
func (r Certs) PinMismatches(ctx context.Context, deviceID string) ([]string, error) {
	if ok, err := atSchema(ctx, r.s.db, CertPinsSchema); err != nil || !ok {
		return nil, err
	}
	rows, err := r.s.queryKey(ctx, deviceID,
		`SELECT serial FROM certs WHERE device_id = ? AND pin_mismatch_at IS NOT NULL ORDER BY serial`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list pin mismatches of %s: %w", deviceID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("list pin mismatches of %s: %w", deviceID, err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PinCert records the fingerprint of a device certificate recorded without
// one, and its CA's unless that is recorded. A certificate with another
// fingerprint keeps it and gets pin_mismatch_at set to Now, once. Result:
// Count, 1 when it pinned the certificate; PinMismatch, true when it recorded
// a mismatch. It fails with ErrNotFound for an unknown certificate.
type PinCert struct {
	Stamp
	Serial      string `json:"serial"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	CAFP        string `json:"ca_fp,omitempty"`
	Now         int64  `json:"now"`
}

// Op implements Command.
func (PinCert) Op() string { return "pin_cert" }

func (PinCert) minSchema() int64 { return CertPinsSchema }

func (c PinCert) apply(ctx context.Context, w *writer) (Result, error) {
	r, err := w.get(ctx, "certs", c.Serial)
	switch {
	case err != nil:
		return Result{}, err
	case r == nil || r.str("device_id") != c.DeviceID:
		return Result{}, ErrNotFound
	case r.isNull("fingerprint"):
		r["fingerprint"] = c.Fingerprint
		if r.isNull("ca_fp") {
			r["ca_fp"] = optString(c.CAFP)
		}
		return Result{Count: 1}, w.put(ctx, "certs", r)
	case r.str("fingerprint") == c.Fingerprint || !r.isNull("pin_mismatch_at"):
		return Result{}, nil
	}
	r["pin_mismatch_at"] = c.Now
	return Result{PinMismatch: true}, w.put(ctx, "certs", r)
}

// Record records a hub node certificate issued to c.NodeID, as RecordCert
// does, with its fingerprints, which it also fills in for a serial recorded
// without them. Below CertPinsSchema the fingerprints are left out of the command:
// a hub whose binary predates them could not decode it.
func (r Hubs) Record(ctx context.Context, c HubCert) error {
	if c.Serial == "" || c.NodeID == "" {
		return errors.New("record hub cert: serial and node ID are required")
	}
	cmd := RecordHubCert{Serial: c.Serial, NodeID: c.NodeID}
	if ok, err := atSchema(ctx, r.s.db, CertPinsSchema); err != nil {
		return fmt.Errorf("record hub cert %s of %s: %w", c.Serial, c.NodeID, err)
	} else if ok {
		cmd.Fingerprint, cmd.CAFP = c.Fingerprint, c.CAFP
	}
	if _, err := r.s.apply(ctx, cmd); err != nil {
		return fmt.Errorf("record hub cert %s of %s: %w", c.Serial, c.NodeID, err)
	}
	return nil
}
