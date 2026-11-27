// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
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
	// CAStageAborted: the rotation was given up before the cutover; the new
	// CA is dropped everywhere.
	CAStageAborted = "aborted"
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
	// certificate it presented to the master that started the rotation.
	Pins      map[string]string
	Stage     string
	StartedAt time.Time
	UpdatedAt time.Time
	// Owner, in a sharded (AP) cluster, is the master that last moved the
	// rotation on (the row's origin): the one that started it, or one that
	// took it over. Empty elsewhere.
	Owner string
}

// Active reports whether the rotation has neither finished nor been aborted.
func (c CARotation) Active() bool { return c.Stage != CAStageFinished && c.Stage != CAStageAborted }

// CARotations is the hub CA rotation repository.
type CARotations struct{ s *Store }

// CARotations returns the hub CA rotation repository.
func (s *Store) CARotations() CARotations { return CARotations{s: s} }

const caRotationColumns = `new_ca_fp, old_ca_fp, new_ca_cert, pins, stage, started_at, updated_at`

// caRotationSelect selects caRotationColumns, and in a sharded cluster the
// row's origin, the rotation's owner.
func (r CARotations) caRotationSelect() string {
	if r.s.shards != nil {
		return `SELECT ` + caRotationColumns + `, _origin`
	}
	return `SELECT ` + caRotationColumns + `, ''`
}

func scanCARotation(row interface{ Scan(...any) error }) (CARotation, error) {
	var (
		c                  CARotation
		pins               string
		started, updatedAt int64
	)
	if err := row.Scan(&c.NewCAFP, &c.OldCAFP, &c.NewCACert, &pins, &c.Stage, &started, &updatedAt, &c.Owner); err != nil {
		return CARotation{}, err
	}
	if err := json.Unmarshal([]byte(pins), &c.Pins); err != nil {
		return CARotation{}, fmt.Errorf("decode pins: %w", err)
	}
	c.StartedAt, c.UpdatedAt = time.UnixMilli(started).UTC(), time.UnixMilli(updatedAt).UTC()
	return c, nil
}

// Latest returns the most recently started rotation, whatever its stage. It
// fails with ErrNotFound when there has been none, and with ErrSchemaTooOld
// below CARotationSchema.
func (r CARotations) Latest(ctx context.Context) (CARotation, error) {
	if ok, err := atSchema(ctx, r.s.db, CARotationSchema); err != nil {
		return CARotation{}, err
	} else if !ok {
		return CARotation{}, fmt.Errorf("read hub CA rotation: %w", ErrSchemaTooOld)
	}
	// In insert order; in a sharded cluster, whose replicas insert the rows
	// in the order they reach them, by start.
	order := ` ORDER BY rowid DESC LIMIT 1`
	if r.s.shards != nil {
		order = ` ORDER BY started_at DESC, new_ca_fp DESC LIMIT 1`
	}
	c, err := scanCARotation(r.s.db.QueryRowContext(ctx, r.caRotationSelect()+` FROM ca_rotations`+order))
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

// Get returns the rotation to the CA whose fingerprint is newCAFP, whatever
// its stage. It fails with ErrNotFound when there is none, and with
// ErrSchemaTooOld below CARotationSchema.
func (r CARotations) Get(ctx context.Context, newCAFP string) (CARotation, error) {
	if ok, err := atSchema(ctx, r.s.db, CARotationSchema); err != nil {
		return CARotation{}, err
	} else if !ok {
		return CARotation{}, fmt.Errorf("read hub CA rotation: %w", ErrSchemaTooOld)
	}
	c, err := scanCARotation(r.s.db.QueryRowContext(ctx,
		r.caRotationSelect()+` FROM ca_rotations WHERE new_ca_fp = ?`, newCAFP))
	if errors.Is(err, sql.ErrNoRows) {
		return CARotation{}, ErrNotFound
	}
	if err != nil {
		return CARotation{}, fmt.Errorf("read hub CA rotation: %w", err)
	}
	return c, nil
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
	return r.advance(ctx, AdvanceCARotation{NewCAFP: newCAFP, From: from, To: to, Now: now.UnixMilli()})
}

// Finish moves the rotation to newCAFP from its cutover to CAStageFinished,
// if the sealed secrets are still those of sealedDigest (see SealedDigest).
func (r CARotations) Finish(ctx context.Context, newCAFP, sealedDigest string, now time.Time) error {
	return r.advance(ctx, AdvanceCARotation{
		NewCAFP: newCAFP, From: CAStageCutover, To: CAStageFinished, Now: now.UnixMilli(), SealedDigest: sealedDigest,
	})
}

func (r CARotations) advance(ctx context.Context, c AdvanceCARotation) error {
	to := c.To
	if _, err := r.s.apply(ctx, c); err != nil {
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
	rows, err := r.s.readEvery(ctx, `
		SELECT 'device', device_id, serial, pin_mismatch_at IS NOT NULL FROM certs
		WHERE revoked_at IS NULL AND (fingerprint IS NULL OR pin_mismatch_at IS NOT NULL)
		UNION ALL
		SELECT 'hub', node_id, serial, 0 FROM hub_certs WHERE revoked_at IS NULL AND fingerprint IS NULL
		ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, fmt.Errorf("list unpinned certificates: %w", err)
	}
	var out []UnpinnedCert
	seen := map[UnpinnedCert]bool{}
	for _, vals := range rows {
		var c UnpinnedCert
		if err := scanVals(vals, []any{&c.Kind, &c.ID, &c.Serial, &c.Mismatch}); err != nil {
			return nil, fmt.Errorf("list unpinned certificates: %w", err)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b UnpinnedCert) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Serial, b.Serial))
	})
	return out, nil
}

// OldCADevices returns the IDs of the devices with an unrevoked certificate
// that have not presented one of the CA caFP on a connection yet: the
// devices a rotation to caFP would cut off. A certificate the hub issued
// counts once the device presented it, which pins its fingerprint.
func (r CARotations) OldCADevices(ctx context.Context, caFP string) ([]string, error) {
	// A device's certificates live on the same replicas, so the subquery
	// sees them all on any member holding the device.
	ids, err := r.s.readEveryString(ctx, `
		SELECT DISTINCT device_id FROM certs c WHERE revoked_at IS NULL AND NOT EXISTS (
			SELECT 1 FROM certs n WHERE n.device_id = c.device_id AND n.revoked_at IS NULL
				AND n.ca_fp = ? AND n.fingerprint IS NOT NULL)`, caFP)
	if err != nil {
		return nil, fmt.Errorf("list devices on the old CA: %w", err)
	}
	return ids, nil
}

// RenewedDevices lists the devices that were handed a certificate of the CA
// caFP: aborting its rotation cuts them off.
func (r CARotations) RenewedDevices(ctx context.Context, caFP string) ([]string, error) {
	ids, err := r.s.readEveryString(ctx, `SELECT DISTINCT device_id FROM certs WHERE revoked_at IS NULL AND ca_fp = ?`, caFP)
	if err != nil {
		return nil, fmt.Errorf("list devices renewed by the new CA: %w", err)
	}
	return ids, nil
}

// readEvery runs query on the local database or, in a sharded cluster, on
// members that together hold every partition, and returns the rows of all:
// a row a replica holds comes once per replica. Each row the query reads
// must be of one partition, or of global tables.
func (s *Store) readEvery(ctx context.Context, query string, args ...any) ([][]any, error) {
	if s.shards == nil {
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		cols, err := rows.Columns()
		if err != nil {
			return nil, err
		}
		var out [][]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return nil, err
			}
			out = append(out, vals)
		}
		return out, rows.Err()
	}
	wargs, err := wireArgs(args)
	if err != nil {
		return nil, err
	}
	parts, err := s.shards.ReadAll(ctx, query, wargs)
	if err != nil {
		return nil, err
	}
	var out [][]any
	for _, p := range parts {
		out = append(out, valuesRows(p.Vals)...)
	}
	return out, nil
}

// readEveryString is readEvery of a query selecting one text column: the
// distinct values, sorted.
func (s *Store) readEveryString(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.readEvery(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, vals := range rows {
		var v string
		if err := scanVals(vals, []any{&v}); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Tables of sealed secrets: each is re-sealed with the new CA's key before a
// rotation finishes.
const (
	SealedKubeClusters   = "kube_clusters"
	SealedProxmoxServers = "proxmox_servers"
	SealedRunbookRuns    = "runbook_runs"
	// SealedConfigDocs holds the sealed notify documents; its other
	// documents are not secret.
	SealedConfigDocs = "config_docs"
	// SealedESPHomeDevices holds the ESPHome devices' connections.
	SealedESPHomeDevices = "esphome_devices"
	// SealedOpenWrtRouters holds the OpenWrt routers' connections.
	SealedOpenWrtRouters = "openwrt_routers"
	// SealedOPNsenseFirewalls holds the OPNsense firewalls' connections.
	SealedOPNsenseFirewalls = "opnsense_firewalls"
)

// sealedColumns maps each table of sealed secrets to its sealed column.
var sealedColumns = map[string]string{
	SealedKubeClusters:   "kubeconfig",
	SealedProxmoxServers: "connection",
	SealedRunbookRuns:    "source",
	SealedConfigDocs:     "content",
	SealedESPHomeDevices: "connection",
	SealedOpenWrtRouters: "connection",
	// OPNsense firewalls (#364).
	SealedOPNsenseFirewalls: "connection",
}

// sealedWhere narrows a table of sealedColumns to its sealed rows, and
// sealedSince is the schema a table of it needs.
var (
	sealedWhere = map[string]string{SealedConfigDocs: ` AND kind = '` + ConfigNotify + `'`}
	sealedSince = map[string]int64{
		SealedConfigDocs: configDocsSchema, SealedESPHomeDevices: esphomeDevicesSchema, SealedOpenWrtRouters: openwrtRoutersSchema,
		SealedOPNsenseFirewalls: opnsenseFirewallsSchema,
	}
)

// SealedSecret is one sealed secret: the row id of table, and its sealed
// value. In ResealSecrets, Sealed is the value read and Resealed the new one.
type SealedSecret struct {
	Table string `json:"table"`
	ID    string `json:"id"`
	// Key, in a sharded cluster, is the partition key of a sharded table's
	// row: where its re-seal is written.
	Key      string `json:"key,omitempty"`
	Sealed   []byte `json:"sealed"`
	Resealed []byte `json:"resealed,omitempty"`
}

// Sealed returns every sealed secret, ordered by table and ID. In a sharded
// cluster the global tables are read here and the runbook runs on members
// that together hold every partition, each run at its newest version.
func (r CARotations) Sealed(ctx context.Context) ([]SealedSecret, error) {
	if r.s.shards == nil {
		return readSealed(ctx, r.s.db)
	}
	out, err := readSealedTables(ctx, r.s.db, SealedKubeClusters, SealedProxmoxServers, SealedConfigDocs, SealedESPHomeDevices,
		SealedOpenWrtRouters, SealedOPNsenseFirewalls)
	if err != nil {
		return nil, err
	}
	rows, err := r.s.readEvery(ctx, `SELECT id, source, runbook_id, _hlc, _origin FROM runbook_runs
		WHERE _deleted = 0`)
	if err != nil {
		return nil, fmt.Errorf("read sealed %s: %w", SealedRunbookRuns, err)
	}
	type version struct {
		hlc    int64
		origin string
	}
	newest := map[string]version{}
	runs := map[string]SealedSecret{}
	for _, vals := range rows {
		var (
			s SealedSecret
			v version
		)
		if err := scanVals(vals, []any{&s.ID, &s.Sealed, &s.Key, &v.hlc, &v.origin}); err != nil {
			return nil, fmt.Errorf("read sealed %s: %w", SealedRunbookRuns, err)
		}
		if old, ok := newest[s.ID]; ok && (v.hlc < old.hlc || (v.hlc == old.hlc && v.origin <= old.origin)) {
			continue
		}
		s.Table = SealedRunbookRuns
		newest[s.ID], runs[s.ID] = v, s
	}
	for _, id := range slices.Sorted(maps.Keys(runs)) {
		out = append(out, runs[id])
	}
	slices.SortStableFunc(out, func(a, b SealedSecret) int {
		return cmp.Or(cmp.Compare(sealedOrder[a.Table], sealedOrder[b.Table]), cmp.Compare(a.ID, b.ID))
	})
	return out, nil
}

// sealedOrder is the order Sealed lists the tables of sealed secrets in.
var sealedOrder = map[string]int{
	SealedKubeClusters: 0, SealedProxmoxServers: 1, SealedRunbookRuns: 2, SealedConfigDocs: 3, SealedESPHomeDevices: 4,
	SealedOpenWrtRouters: 5, SealedOPNsenseFirewalls: 6,
}

// SealedDigest is a digest of secrets, as Sealed returns them: finishing a
// rotation names the digest of the secrets checked to be sealed with the new
// key, and is refused if any changed since. It is empty for no secrets.
func SealedDigest(secrets []SealedSecret) string {
	if len(secrets) == 0 {
		return ""
	}
	h := sha256.New()
	for _, s := range secrets {
		for _, b := range [][]byte{[]byte(s.Table), []byte(s.ID), s.Sealed} {
			_ = binary.Write(h, binary.BigEndian, uint64(len(b)))
			h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// sealedQuerier reads sealed secrets: a database or a transaction.
type sealedQuerier interface {
	querier
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readSealed(ctx context.Context, q sealedQuerier) ([]SealedSecret, error) {
	return readSealedTables(ctx, q, SealedKubeClusters, SealedProxmoxServers, SealedRunbookRuns, SealedConfigDocs,
		SealedESPHomeDevices, SealedOpenWrtRouters, SealedOPNsenseFirewalls)
}

// readSealedTables reads the sealed secrets of tables, in that order.
func readSealedTables(ctx context.Context, q sealedQuerier, tables ...string) ([]SealedSecret, error) {
	v, err := schemaVersion(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("read sealed: %w", err)
	}
	versioned := v >= VersionedSchema
	var out []SealedSecret
	for _, table := range tables {
		if v < sealedSince[table] {
			continue
		}
		// table, column and the conditions are constants of this file. A
		// tombstone keeps no secret.
		where := ` WHERE 1 = 1`
		if versioned {
			where += ` AND _deleted = 0`
		}
		where += sealedWhere[table]
		rows, err := q.QueryContext(ctx, `SELECT id, `+sealedColumns[table]+` FROM `+table+where+` ORDER BY id`)
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
	Stamp
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

func (c StartCARotation) apply(ctx context.Context, w *writer) (Result, error) {
	active, err := w.query(ctx, "ca_rotations", `stage NOT IN ('`+CAStageFinished+`', '`+CAStageAborted+`')`, "")
	if err != nil {
		return Result{}, err
	}
	if len(active) > 0 {
		return Result{}, ErrCARotationActive
	}
	return Result{}, w.insert(ctx, "ca_rotations", row{
		"new_ca_fp": c.NewCAFP, "old_ca_fp": c.OldCAFP, "new_ca_cert": c.NewCACert, "pins": c.Pins,
		"stage": CAStageStarted, "started_at": c.Now, "updated_at": c.Now,
	})
}

// AdvanceCARotation moves the rotation to the CA NewCAFP from stage From to
// stage To: started to cutover, cutover to finished, or started to aborted.
type AdvanceCARotation struct {
	Stamp
	NewCAFP string `json:"new_ca_fp"`
	From    string `json:"from"`
	To      string `json:"to"`
	Now     int64  `json:"now"`
	// SealedDigest, for the step to CAStageFinished, is the SealedDigest of
	// the sealed secrets checked to be sealed with the new key: the step is
	// refused if any secret changed since, as one sealed with the old key
	// after the check would be lost when the old key goes.
	SealedDigest string `json:"sealed_digest,omitempty"`
}

// Op implements Command.
func (AdvanceCARotation) Op() string { return "advance_ca_rotation" }

func (AdvanceCARotation) minSchema() int64 { return CARotationSchema }

func (c AdvanceCARotation) apply(ctx context.Context, w *writer) (Result, error) {
	if step := c.From + ">" + c.To; step != CAStageStarted+">"+CAStageCutover && step != CAStageCutover+">"+CAStageFinished &&
		step != CAStageStarted+">"+CAStageAborted {
		return Result{}, fmt.Errorf("%w: no step from %q to %q", ErrCARotationConflict, c.From, c.To)
	}
	if c.To == CAStageAborted {
		// Certificates the aborted CA issued, to agents and hubs, are revoked:
		// nothing trusts that CA any more, and its key may live on in a copy.
		// A sharded cluster revokes the agents' on every shard
		// (RevokeCACerts).
		tables := []string{"certs", "hub_certs"}
		if w.s.Sharded() {
			tables = tables[1:]
		}
		for _, table := range tables {
			if _, err := revokeWhere(ctx, w, table, `ca_fp = ?`, c.Now, c.NewCAFP); err != nil {
				return Result{}, err
			}
		}
	}
	// A sharded cluster's secrets live on many members: the master
	// finishing the rotation checks them all (cluster.APNode.FinishCA).
	if c.To == CAStageFinished && !w.s.Sharded() {
		secrets, err := readSealed(ctx, w.tx)
		if err != nil {
			return Result{}, err
		}
		if SealedDigest(secrets) != c.SealedDigest {
			return Result{}, fmt.Errorf("%w: sealed secrets changed since they were checked", ErrCARotationConflict)
		}
	}
	r, err := w.get(ctx, "ca_rotations", c.NewCAFP)
	if err != nil {
		return Result{}, err
	}
	if r == nil || r.str("stage") != c.From {
		return Result{}, ErrCARotationConflict
	}
	r["stage"], r["updated_at"] = c.To, c.Now
	return Result{}, w.put(ctx, "ca_rotations", r)
}

// ResealSecrets replaces sealed secrets with the same secrets sealed with
// the new CA's key, during the cutover of the rotation to NewCAFP. Each
// secret is replaced only from the value it was read at; one that changed
// fails the whole command.
type ResealSecrets struct {
	Stamp
	NewCAFP string         `json:"new_ca_fp"`
	Secrets []SealedSecret `json:"secrets"`
}

// Op implements Command.
func (ResealSecrets) Op() string { return "reseal_secrets" }

func (ResealSecrets) minSchema() int64 { return CARotationSchema }

func (c ResealSecrets) apply(ctx context.Context, w *writer) (Result, error) {
	// In a sharded cluster a replica of a runbook's runs may not have the
	// rotation's last step yet: the master re-sealing checked it.
	if !w.s.Sharded() {
		rot, err := w.get(ctx, "ca_rotations", c.NewCAFP)
		if err != nil {
			return Result{}, err
		}
		if rot == nil || rot.str("stage") != CAStageCutover {
			return Result{}, fmt.Errorf("%w: the rotation is not at its cutover", ErrCARotationConflict)
		}
	}
	for _, s := range c.Secrets {
		col, ok := sealedColumns[s.Table]
		if !ok {
			return Result{}, fmt.Errorf("%w: no sealed secrets in %q", ErrCARotationConflict, s.Table)
		}
		if len(s.Resealed) == 0 || bytes.Equal(s.Sealed, s.Resealed) {
			continue
		}
		r, err := w.get(ctx, s.Table, s.ID)
		if err != nil {
			return Result{}, err
		}
		if cur, _ := r[col].([]byte); r == nil || !bytes.Equal(cur, s.Sealed) {
			return Result{}, fmt.Errorf("%w: %s %s", ErrCARotationConflict, s.Table, s.ID)
		}
		r[col] = s.Resealed
		if err := w.put(ctx, s.Table, r); err != nil {
			return Result{}, err
		}
	}
	return Result{}, nil
}

// RevokeCACerts revokes, in a sharded cluster, the device certificates the
// CA CAFP issued: it runs on every storage member, on the shards it holds,
// when the rotation to CAFP is aborted.
type RevokeCACerts struct {
	Stamp
	CAFP string `json:"ca_fp"`
	Now  int64  `json:"now"`
}

// RevokeCerts revokes the device certificates the CA caFP issued, on every
// shard (RevokeCACerts), and returns how many.
func (r CARotations) RevokeCerts(ctx context.Context, caFP string, now time.Time) (int, error) {
	res, err := r.s.apply(ctx, RevokeCACerts{CAFP: caFP, Now: now.UnixMilli()})
	if err != nil {
		return 0, fmt.Errorf("revoke the certificates of CA %s: %w", caFP, err)
	}
	return res.Count, nil
}

// Op implements Command.
func (RevokeCACerts) Op() string { return "revoke_ca_certs" }

func (RevokeCACerts) minSchema() int64 { return CARotationSchema }

func (c RevokeCACerts) apply(ctx context.Context, w *writer) (Result, error) {
	n, err := revokeWhere(ctx, w, "certs", `ca_fp = ?`, c.Now, c.CAFP)
	return Result{Count: n}, err
}
