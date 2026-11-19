// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CARotationSchema is the schema version whose migration (ca_rotation) added
// the ca_rotations table. Every command of a hub CA rotation needs it.
const CARotationSchema = 25

// Stages of a hub CA rotation.
const (
	// CAStageStarted: every hub trusts both CAs and serves the old one;
	// new certificates are signed by the new one.
	CAStageStarted = "started"
	// CAStageCutover: every hub serves the new CA.
	CAStageCutover = "cutover"
	// CAStageFinished: the old CA is no longer trusted and its key is gone.
	CAStageFinished = "finished"
)

// ErrCARotationActive is returned when starting a hub CA rotation while one
// is under way.
var ErrCARotationActive = errors.New("a hub CA rotation is under way")

// ErrCARotationConflict is returned when advancing a hub CA rotation, or
// re-sealing secrets for it, from a state that changed since it was read.
var ErrCARotationConflict = errors.New("the hub CA rotation or a sealed secret changed since it was read")

// CARotation is a hub CA rotation.
type CARotation struct {
	// NewCAFP and OldCAFP are the fingerprints (pki.FingerprintHex) of the
	// new CA's certificate and of the one it replaces.
	NewCAFP string
	OldCAFP string
	// NewCACert is the new CA's certificate, PEM. Its key is never stored.
	NewCACert string
	// Pins maps each hub's node ID to the fingerprint of the node
	// certificate it presented to the leader when the rotation started.
	Pins      map[string]string
	Stage     string
	StartedAt time.Time
	UpdatedAt time.Time
}

// Active reports whether the rotation has not finished.
func (c CARotation) Active() bool { return c.Stage != CAStageFinished }

// CARotations is the hub CA rotation repository.
type CARotations struct{ s *Store }

// CARotations returns the hub CA rotation repository.
func (s *Store) CARotations() CARotations { return CARotations{s: s} }

const caRotationColumns = `new_ca_fp, old_ca_fp, new_ca_cert, pins, stage, started_at, updated_at`

func scanCARotation(row interface{ Scan(...any) error }) (CARotation, error) {
	var (
		c                  CARotation
		pins               string
		started, updatedAt int64
	)
	if err := row.Scan(&c.NewCAFP, &c.OldCAFP, &c.NewCACert, &pins, &c.Stage, &started, &updatedAt); err != nil {
		return CARotation{}, err
	}
	if err := json.Unmarshal([]byte(pins), &c.Pins); err != nil {
		return CARotation{}, fmt.Errorf("decode pins: %w", err)
	}
	c.StartedAt, c.UpdatedAt = time.UnixMilli(started).UTC(), time.UnixMilli(updatedAt).UTC()
	return c, nil
}

// Latest returns the most recently started rotation, finished or not. It
// fails with ErrNotFound when there has been none, and with ErrSchemaTooOld
// below CARotationSchema.
func (r CARotations) Latest(ctx context.Context) (CARotation, error) {
	if ok, err := atSchema(ctx, r.s.db, CARotationSchema); err != nil {
		return CARotation{}, err
	} else if !ok {
		return CARotation{}, fmt.Errorf("read hub CA rotation: %w", ErrSchemaTooOld)
	}
	c, err := scanCARotation(r.s.db.QueryRowContext(ctx,
		`SELECT `+caRotationColumns+` FROM ca_rotations ORDER BY started_at DESC, new_ca_fp LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return CARotation{}, ErrNotFound
	}
	if err != nil {
		return CARotation{}, fmt.Errorf("read hub CA rotation: %w", err)
	}
	return c, nil
}

// Active returns the rotation under way. It fails with ErrNotFound when
// there is none, and with ErrSchemaTooOld below CARotationSchema.
func (r CARotations) Active(ctx context.Context) (CARotation, error) {
	c, err := r.Latest(ctx)
	if err == nil && !c.Active() {
		return CARotation{}, ErrNotFound
	}
	return c, err
}

// Start records a new rotation at CAStageStarted. It fails with
// ErrCARotationActive while another is under way.
func (r CARotations) Start(ctx context.Context, c CARotation, now time.Time) error {
	pins, err := json.Marshal(c.Pins)
	if err != nil {
		return fmt.Errorf("start hub CA rotation: %w", err)
	}
	if _, err := r.s.apply(ctx, StartCARotation{
		NewCAFP: c.NewCAFP, OldCAFP: c.OldCAFP, NewCACert: c.NewCACert, Pins: string(pins), Now: now.UnixMilli(),
	}); err != nil {
		return fmt.Errorf("start hub CA rotation: %w", err)
	}
	return nil
}

// Advance moves the rotation to the new CA newCAFP from stage from to stage
// to. It fails with ErrCARotationConflict when the rotation is not at from.
func (r CARotations) Advance(ctx context.Context, newCAFP, from, to string, now time.Time) error {
	if _, err := r.s.apply(ctx, AdvanceCARotation{NewCAFP: newCAFP, From: from, To: to, Now: now.UnixMilli()}); err != nil {
		return fmt.Errorf("advance hub CA rotation to %s: %w", to, err)
	}
	return nil
}

// UnpinnedCert is an unrevoked certificate a rotation could not renew safely:
// one without a recorded fingerprint, or one whose serial someone presented
// with another certificate.
type UnpinnedCert struct {
	// Kind is "device" or "hub".
	Kind   string
	ID     string
	Serial string
	// Mismatch is true for a recorded pin mismatch, false for no fingerprint.
	Mismatch bool
}

// Unpinned returns the unrevoked device and hub certificates without a
// recorded fingerprint or with a recorded mismatch, by kind, ID and serial.
func (r CARotations) Unpinned(ctx context.Context) ([]UnpinnedCert, error) {
	rows, err := r.s.db.QueryContext(ctx, `
		SELECT 'device', device_id, serial, pin_mismatch_at IS NOT NULL FROM certs
		WHERE revoked_at IS NULL AND (fingerprint IS NULL OR pin_mismatch_at IS NOT NULL)
		UNION ALL
		SELECT 'hub', node_id, serial, 0 FROM hub_certs WHERE revoked_at IS NULL AND fingerprint IS NULL
		ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, fmt.Errorf("list unpinned certificates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []UnpinnedCert
	for rows.Next() {
		var c UnpinnedCert
		if err := rows.Scan(&c.Kind, &c.ID, &c.Serial, &c.Mismatch); err != nil {
			return nil, fmt.Errorf("list unpinned certificates: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// OldCADevices returns the IDs of the devices with an unrevoked certificate
// that have not presented one of the CA caFP on a connection yet: the
// devices a rotation to caFP would cut off. A certificate the hub issued
// counts once the device presented it, which pins its fingerprint.
func (r CARotations) OldCADevices(ctx context.Context, caFP string) ([]string, error) {
	rows, err := r.s.db.QueryContext(ctx, `
		SELECT DISTINCT device_id FROM certs c WHERE revoked_at IS NULL AND NOT EXISTS (
			SELECT 1 FROM certs n WHERE n.device_id = c.device_id AND n.revoked_at IS NULL
				AND n.ca_fp = ? AND n.fingerprint IS NOT NULL)
		ORDER BY device_id`, caFP)
	if err != nil {
		return nil, fmt.Errorf("list devices on the old CA: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("list devices on the old CA: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Tables of sealed secrets: each is re-sealed with the new CA's key before a
// rotation finishes.
const (
	SealedKubeClusters   = "kube_clusters"
	SealedProxmoxServers = "proxmox_servers"
	SealedRunbookRuns    = "runbook_runs"
)

// sealedColumns maps each table of sealed secrets to its sealed column.
var sealedColumns = map[string]string{
	SealedKubeClusters:   "kubeconfig",
	SealedProxmoxServers: "connection",
	SealedRunbookRuns:    "source",
}

// SealedSecret is one sealed secret: the row id of table, and its sealed
// value. In ResealSecrets, Sealed is the value read and Resealed the new one.
type SealedSecret struct {
	Table    string `json:"table"`
	ID       string `json:"id"`
	Sealed   []byte `json:"sealed"`
	Resealed []byte `json:"resealed,omitempty"`
}

// Sealed returns every sealed secret, ordered by table and ID.
func (r CARotations) Sealed(ctx context.Context) ([]SealedSecret, error) {
	var out []SealedSecret
	for _, table := range []string{SealedKubeClusters, SealedProxmoxServers, SealedRunbookRuns} {
		// table and column are constants of this file.
		rows, err := r.s.db.QueryContext(ctx, `SELECT id, `+sealedColumns[table]+` FROM `+table+` ORDER BY id`) //nolint:gosec // see above
		if err != nil {
			return nil, fmt.Errorf("read sealed %s: %w", table, err)
		}
		for rows.Next() {
			s := SealedSecret{Table: table}
			if err := rows.Scan(&s.ID, &s.Sealed); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("read sealed %s: %w", table, err)
			}
			out = append(out, s)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("read sealed %s: %w", table, err)
		}
	}
	return out, nil
}

// Reseal replaces each secret's Sealed value with its Resealed one, all or
// none, during the cutover of the rotation to newCAFP. It fails with
// ErrCARotationConflict when any secret changed since it was read.
func (r CARotations) Reseal(ctx context.Context, newCAFP string, secrets []SealedSecret) error {
	if len(secrets) == 0 {
		return nil
	}
	if _, err := r.s.apply(ctx, ResealSecrets{NewCAFP: newCAFP, Secrets: secrets}); err != nil {
		return fmt.Errorf("re-seal %d secrets: %w", len(secrets), err)
	}
	return nil
}

// StartCARotation records a hub CA rotation at CAStageStarted; there must be
// none under way.
type StartCARotation struct {
	NewCAFP   string `json:"new_ca_fp"`
	OldCAFP   string `json:"old_ca_fp"`
	NewCACert string `json:"new_ca_cert"`
	// Pins is the JSON object of CARotation.Pins.
	Pins string `json:"pins"`
	Now  int64  `json:"now"`
}

// Op implements Command.
func (StartCARotation) Op() string { return "start_ca_rotation" }

func (StartCARotation) minSchema() int64 { return CARotationSchema }

func (c StartCARotation) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ca_rotations WHERE stage != '`+CAStageFinished+`'`).Scan(&n); err != nil {
		return Result{}, err
	}
	if n > 0 {
		return Result{}, ErrCARotationActive
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO ca_rotations (`+caRotationColumns+`)
		VALUES (?, ?, ?, ?, '`+CAStageStarted+`', ?, ?)`,
		c.NewCAFP, c.OldCAFP, c.NewCACert, c.Pins, c.Now, c.Now)
	return Result{}, err
}

// AdvanceCARotation moves the rotation to the CA NewCAFP from stage From to
// stage To: started to cutover, or cutover to finished.
type AdvanceCARotation struct {
	NewCAFP string `json:"new_ca_fp"`
	From    string `json:"from"`
	To      string `json:"to"`
	Now     int64  `json:"now"`
}

// Op implements Command.
func (AdvanceCARotation) Op() string { return "advance_ca_rotation" }

func (AdvanceCARotation) minSchema() int64 { return CARotationSchema }

func (c AdvanceCARotation) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	if !(c.From == CAStageStarted && c.To == CAStageCutover) && !(c.From == CAStageCutover && c.To == CAStageFinished) {
		return Result{}, fmt.Errorf("%w: no step from %q to %q", ErrCARotationConflict, c.From, c.To)
	}
	res, err := tx.ExecContext(ctx, `UPDATE ca_rotations SET stage = ?, updated_at = ? WHERE new_ca_fp = ? AND stage = ?`,
		c.To, c.Now, c.NewCAFP, c.From)
	if err != nil {
		return Result{}, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return Result{}, err
	} else if n == 0 {
		return Result{}, ErrCARotationConflict
	}
	return Result{}, nil
}

// ResealSecrets replaces sealed secrets with the same secrets sealed with
// the new CA's key, during the cutover of the rotation to NewCAFP. Each
// secret is replaced only from the value it was read at; one that changed
// fails the whole command.
type ResealSecrets struct {
	NewCAFP string         `json:"new_ca_fp"`
	Secrets []SealedSecret `json:"secrets"`
}

// Op implements Command.
func (ResealSecrets) Op() string { return "reseal_secrets" }

func (ResealSecrets) minSchema() int64 { return CARotationSchema }

func (c ResealSecrets) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	var stage string
	err := tx.QueryRowContext(ctx, `SELECT stage FROM ca_rotations WHERE new_ca_fp = ?`, c.NewCAFP).Scan(&stage)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && stage != CAStageCutover) {
		return Result{}, fmt.Errorf("%w: the rotation is not at its cutover", ErrCARotationConflict)
	}
	if err != nil {
		return Result{}, err
	}
	for _, s := range c.Secrets {
		col, ok := sealedColumns[s.Table]
		if !ok {
			return Result{}, fmt.Errorf("%w: no sealed secrets in %q", ErrCARotationConflict, s.Table)
		}
		if len(s.Resealed) == 0 || bytes.Equal(s.Sealed, s.Resealed) {
			continue
		}
		// s.Table and col are keys and values of sealedColumns.
		res, err := tx.ExecContext(ctx, `UPDATE `+s.Table+` SET `+col+` = ? WHERE id = ? AND `+col+` = ?`, //nolint:gosec // see above
			s.Resealed, s.ID, s.Sealed)
		if err != nil {
			return Result{}, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return Result{}, err
		} else if n == 0 {
			return Result{}, fmt.Errorf("%w: %s %s", ErrCARotationConflict, s.Table, s.ID)
		}
	}
	return Result{}, nil
}
