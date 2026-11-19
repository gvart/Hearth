// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Command is a typed, serializable description of one store write. It carries
// every non-deterministic input (timestamps, hashes, encoded JSON), so applying
// the same sequence of commands to the same starting state yields the same
// rows on every node. Commands are built by the repository methods; the set is
// closed to this package.
//
// Timestamps are unix milliseconds (UTC), matching the schema. JSON documents
// (facts, labels, detail) are carried as strings so they are stored byte for
// byte as the caller passed them, whether applied directly or after a round
// trip through EncodeCommand.
type Command interface {
	// Op is the command's stable name in its encoded form.
	Op() string
	// apply executes the command inside tx.
	apply(ctx context.Context, tx *sql.Tx) (Result, error)
}

// Result is what applying a Command returns. Each command fills only the
// fields documented on it; the rest stay zero.
type Result struct {
	// Device is the row written by a single-device command.
	Device Device
	// PrevStatus is the device's status before ReportFacts or MarkSeen.
	PrevStatus string
	// Devices are the rows changed by MarkOffline or MarkDevicesOffline,
	// ordered by ID.
	Devices []Device
	// Labels are the labels of the token consumed by ConsumeToken.
	Labels map[string]string
	// ApprovalID is the approval of the link spent by UseApprovalLink.
	ApprovalID string
	// ID is the audit_log ID assigned by AppendAudit.
	ID int64
	// Count is the number of certificates revoked by RevokeDevice or
	// RevokeHubCerts, of devices updated by MarkSeenBatch, or of hosts
	// recorded by RecordNetworkScan.
	Count int
	// NewHosts and ReturnedHosts are the hosts RecordNetworkScan found for
	// the first time, and back after an absence.
	NewHosts      []NetworkHost
	ReturnedHosts []NetworkHost
}

// UpsertDevice inserts a device or replaces every field but first_seen.
type UpsertDevice struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Facts     string `json:"facts"`
	Labels    string `json:"labels"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	Status    string `json:"status"`
	// BootTime is nil when unknown.
	BootTime *int64 `json:"boot_time,omitempty"`
}

// Op implements Command.
func (UpsertDevice) Op() string { return "upsert_device" }

func (c UpsertDevice) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO devices (id, name, hostname, os, arch, facts, labels, first_seen, last_seen, status, boot_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = excluded.name, hostname = excluded.hostname, os = excluded.os,
			arch = excluded.arch, facts = excluded.facts, labels = excluded.labels,
			last_seen = excluded.last_seen, status = excluded.status, boot_time = excluded.boot_time`,
		c.ID, c.Name, c.Hostname, c.OS, c.Arch, c.Facts, c.Labels,
		c.FirstSeen, c.LastSeen, c.Status, nullInt(c.BootTime))
	return Result{}, err
}

// ReportFacts records facts reported by a device and marks it online.
// Result: Device, PrevStatus.
type ReportFacts struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Facts    string `json:"facts"`
	Now      int64  `json:"now"`
}

// Op implements Command.
func (ReportFacts) Op() string { return "report_facts" }

func (c ReportFacts) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	return updateDevice(ctx, tx, c.ID,
		`hostname = ?, os = ?, arch = ?, facts = ?, last_seen = ?, status = '`+StatusOnline+`'`,
		c.Hostname, c.OS, c.Arch, c.Facts, c.Now)
}

// MarkSeen sets a device's last_seen and marks it online.
// Result: Device, PrevStatus.
type MarkSeen struct {
	ID  string `json:"id"`
	Now int64  `json:"now"`
}

// Op implements Command.
func (MarkSeen) Op() string { return "mark_seen" }

func (c MarkSeen) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	return updateDevice(ctx, tx, c.ID, `last_seen = ?, status = '`+StatusOnline+`'`, c.Now)
}

// updateDevice applies set to device id and returns the updated row and the
// status it had before, or ErrNotFound.
func updateDevice(ctx context.Context, tx *sql.Tx, id, set string, args ...any) (Result, error) {
	var prev string
	err := tx.QueryRowContext(ctx, `SELECT status FROM devices WHERE id = ?`, id).Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, err
	}
	// set is a constant from this file's callers; values are bound parameters.
	row := tx.QueryRowContext(ctx, `UPDATE devices SET `+set+` WHERE id = ? RETURNING `+deviceColumns, //nolint:gosec // see above
		append(args, id)...)
	d, err := scanDevice(row)
	if err != nil {
		return Result{}, err
	}
	return Result{Device: d, PrevStatus: prev}, nil
}

// SetBootTime sets or clears a device's boot time. Result: Device.
type SetBootTime struct {
	ID string `json:"id"`
	// BootTime is nil to clear it.
	BootTime *int64 `json:"boot_time,omitempty"`
}

// Op implements Command.
func (SetBootTime) Op() string { return "set_boot_time" }

func (c SetBootTime) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	row := tx.QueryRowContext(ctx, `UPDATE devices SET boot_time = ? WHERE id = ? RETURNING `+deviceColumns,
		nullInt(c.BootTime), c.ID)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Device: d}, nil
}

// MarkOffline marks every online device last seen before Cutoff as offline.
// Result: Devices.
type MarkOffline struct {
	Cutoff int64 `json:"cutoff"`
}

// Op implements Command.
func (MarkOffline) Op() string { return "mark_offline" }

func (c MarkOffline) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	rows, err := tx.QueryContext(ctx, `
		UPDATE devices SET status = '`+StatusOffline+`'
		WHERE status = '`+StatusOnline+`' AND last_seen < ?
		RETURNING `+deviceColumns, c.Cutoff)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return Result{}, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}
	slices.SortFunc(out, func(a, b Device) int { return strings.Compare(a.ID, b.ID) })
	return Result{Devices: out}, nil
}

// Seen is one device's last heartbeat in a MarkSeenBatch.
type Seen struct {
	ID       string `json:"id"`
	LastSeen int64  `json:"last_seen"`
}

// MarkSeenBatch records the last heartbeat of many devices at once. A
// clustered hub coalesces heartbeats in memory and flushes them with this
// command, so last_seen does not cost a Raft round per heartbeat. It only
// moves last_seen forward and never changes a status: presence transitions
// go through MarkSeen and MarkDevicesOffline. Unknown devices are skipped.
// Result: Count, the number of rows changed.
type MarkSeenBatch struct {
	Seen []Seen `json:"seen"`
}

// Op implements Command.
func (MarkSeenBatch) Op() string { return "mark_seen_batch" }

func (c MarkSeenBatch) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	n := 0
	for _, s := range c.Seen {
		res, err := tx.ExecContext(ctx,
			`UPDATE devices SET last_seen = ? WHERE id = ? AND last_seen < ?`, s.LastSeen, s.ID, s.LastSeen)
		if err != nil {
			return Result{}, err
		}
		k, err := res.RowsAffected()
		if err != nil {
			return Result{}, err
		}
		n += int(k)
	}
	return Result{Count: n}, nil
}

// MarkDevicesOffline marks the listed devices offline if they are online. A
// clustered leader decides who is silent from its in-memory view of
// heartbeats (see MarkSeenBatch) and names them, rather than comparing the
// stored last_seen with a cutoff as MarkOffline does. Result: Devices, the
// rows changed, ordered by ID.
type MarkDevicesOffline struct {
	IDs []string `json:"ids"`
}

// Op implements Command.
func (MarkDevicesOffline) Op() string { return "mark_devices_offline" }

func (c MarkDevicesOffline) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	var out []Device
	for _, id := range c.IDs {
		row := tx.QueryRowContext(ctx, `
			UPDATE devices SET status = '`+StatusOffline+`'
			WHERE id = ? AND status = '`+StatusOnline+`'
			RETURNING `+deviceColumns, id)
		d, err := scanDevice(row)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return Result{}, err
		}
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Device) int { return strings.Compare(a.ID, b.ID) })
	return Result{Devices: out}, nil
}

// SetHubURL records the agent-facing URL of a cluster hub. Each hub writes
// its own row when it starts; agents are sent these URLs to fail over to.
type SetHubURL struct {
	NodeID   string `json:"node_id"`
	AgentURL string `json:"agent_url"`
}

// Op implements Command.
func (SetHubURL) Op() string { return "set_hub_url" }

func (c SetHubURL) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO cluster_hubs (node_id, agent_url) VALUES (?, ?)
		ON CONFLICT (node_id) DO UPDATE SET agent_url = excluded.agent_url`, c.NodeID, c.AgentURL)
	return Result{}, err
}

// RecordHubCert records a hub node certificate issued to a cluster node.
// Recording a known serial again is a no-op: it never clears a revocation.
//
// From schema 23 it also records the certificate's Fingerprint and the
// fingerprint of the CA that issued it (CAFP), and fills them in for a known
// serial of the same node recorded without them. Below that schema they are
// dropped, the same way on every node.
type RecordHubCert struct {
	Serial      string `json:"serial"`
	NodeID      string `json:"node_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
	CAFP        string `json:"ca_fp,omitempty"`
}

// Op implements Command.
func (RecordHubCert) Op() string { return "record_hub_cert" }

func (RecordHubCert) minSchema() int64 { return hubCertsSchema }

func (c RecordHubCert) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	pinned, err := atSchema(ctx, tx, CARotationSchema)
	if err != nil {
		return Result{}, err
	}
	if !pinned {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO hub_certs (serial, node_id) VALUES (?, ?) ON CONFLICT (serial) DO NOTHING`, c.Serial, c.NodeID)
		return Result{}, err
	}
	// A known serial keeps its node ID and revocation; only a missing
	// fingerprint is filled in.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO hub_certs (serial, node_id, fingerprint, ca_fp) VALUES (?, ?, ?, ?)
		ON CONFLICT (serial) DO UPDATE SET
			fingerprint = COALESCE(hub_certs.fingerprint, excluded.fingerprint),
			ca_fp = COALESCE(hub_certs.ca_fp, excluded.ca_fp)
		WHERE hub_certs.node_id = excluded.node_id`,
		c.Serial, c.NodeID, nullString(c.Fingerprint), nullString(c.CAFP))
	return Result{}, err
}

// RevokeHubCerts revokes every unrevoked hub certificate recorded for a node
// at Now. Result: Count, which is zero when there was nothing to revoke.
type RevokeHubCerts struct {
	NodeID string `json:"node_id"`
	Now    int64  `json:"now"`
}

// Op implements Command.
func (RevokeHubCerts) Op() string { return "revoke_hub_certs" }

func (RevokeHubCerts) minSchema() int64 { return hubCertsSchema }

func (c RevokeHubCerts) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	res, err := tx.ExecContext(ctx,
		`UPDATE hub_certs SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL`, c.Now, c.NodeID)
	if err != nil {
		return Result{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Result{}, err
	}
	return Result{Count: int(n)}, nil
}

// CreateToken stores a single-use enrollment token by its SHA-256 hash.
type CreateToken struct {
	Hash      []byte `json:"hash"`
	Labels    string `json:"labels"`
	ExpiresAt int64  `json:"expires_at"`
}

// Op implements Command.
func (CreateToken) Op() string { return "create_token" }

func (c CreateToken) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO tokens (hash, labels, expires_at) VALUES (?, ?, ?)`, c.Hash, c.Labels, c.ExpiresAt)
	return Result{}, err
}

// ConsumeToken marks a token used at Now if it is unused and unexpired. The
// outcome is decided inside apply, so exactly one ConsumeToken per token wins
// however often the log is replayed. Result: Labels. It fails with
// ErrNotFound, ErrTokenUsed or ErrTokenExpired.
type ConsumeToken struct {
	Hash []byte `json:"hash"`
	Now  int64  `json:"now"`
}

// Op implements Command.
func (ConsumeToken) Op() string { return "consume_token" }

func (c ConsumeToken) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	var labels string
	err := tx.QueryRowContext(ctx, `
		UPDATE tokens SET used_at = ?
		WHERE hash = ? AND used_at IS NULL AND expires_at > ?
		RETURNING labels`, c.Now, c.Hash, c.Now).Scan(&labels)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, whyUnusable(ctx, tx, c.Hash, c.Now)
	}
	if err != nil {
		return Result{}, err
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(labels), &out); err != nil {
		return Result{}, fmt.Errorf("decode labels: %w", err)
	}
	return Result{Labels: out}, nil
}

// whyUnusable explains a failed ConsumeToken. It only classifies the error;
// the atomic decision has already been made by the UPDATE.
func whyUnusable(ctx context.Context, tx *sql.Tx, hash []byte, nowMs int64) error {
	var (
		expiresAt int64
		usedAt    sql.NullInt64
	)
	err := tx.QueryRowContext(ctx, `SELECT expires_at, used_at FROM tokens WHERE hash = ?`, hash).
		Scan(&expiresAt, &usedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	case usedAt.Valid:
		return ErrTokenUsed
	case expiresAt <= nowMs:
		return ErrTokenExpired
	default:
		return errors.New("token not consumed") // unreachable: same transaction as the UPDATE
	}
}

// CreateJoinToken stores a single-use cluster join token by its SHA-256 hash.
type CreateJoinToken struct {
	Hash      []byte `json:"hash"`
	ExpiresAt int64  `json:"expires_at"`
}

// Op implements Command.
func (CreateJoinToken) Op() string { return "create_join_token" }

func (c CreateJoinToken) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx, `INSERT INTO join_tokens (hash, expires_at) VALUES (?, ?)`, c.Hash, c.ExpiresAt)
	return Result{}, err
}

// ConsumeJoinToken marks a join token used at Now if it is unused and
// unexpired, deciding inside apply like ConsumeToken. It fails with
// ErrNotFound, ErrTokenUsed or ErrTokenExpired.
type ConsumeJoinToken struct {
	Hash []byte `json:"hash"`
	Now  int64  `json:"now"`
}

// Op implements Command.
func (ConsumeJoinToken) Op() string { return "consume_join_token" }

func (c ConsumeJoinToken) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	res, err := tx.ExecContext(ctx, `
		UPDATE join_tokens SET used_at = ?
		WHERE hash = ? AND used_at IS NULL AND expires_at > ?`, c.Now, c.Hash, c.Now)
	if err != nil {
		return Result{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Result{}, err
	}
	if n == 1 {
		return Result{}, nil
	}
	var (
		expiresAt int64
		usedAt    sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `SELECT expires_at, used_at FROM join_tokens WHERE hash = ?`, c.Hash).
		Scan(&expiresAt, &usedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Result{}, ErrNotFound
	case err != nil:
		return Result{}, err
	case usedAt.Valid:
		return Result{}, ErrTokenUsed
	default:
		return Result{}, ErrTokenExpired
	}
}

// CreateCert records a certificate issued to a device. From schema 23 it also
// records the certificate's Fingerprint and the fingerprint of the CA that
// issued it (CAFP); below that schema they are dropped, the same way on every
// node.
type CreateCert struct {
	Serial      string `json:"serial"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
	CAFP        string `json:"ca_fp,omitempty"`
}

// Op implements Command.
func (CreateCert) Op() string { return "create_cert" }

func (c CreateCert) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	pinned, err := atSchema(ctx, tx, CARotationSchema)
	if err != nil {
		return Result{}, err
	}
	if !pinned {
		_, err := tx.ExecContext(ctx, `INSERT INTO certs (serial, device_id) VALUES (?, ?)`, c.Serial, c.DeviceID)
		return Result{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO certs (serial, device_id, fingerprint, ca_fp) VALUES (?, ?, ?, ?)`,
		c.Serial, c.DeviceID, nullString(c.Fingerprint), nullString(c.CAFP))
	return Result{}, err
}

// RevokeDevice revokes every unrevoked certificate of a device at Now.
// Result: Count. It fails with ErrNotFound if the device has no certificates.
type RevokeDevice struct {
	DeviceID string `json:"device_id"`
	Now      int64  `json:"now"`
}

// Op implements Command.
func (RevokeDevice) Op() string { return "revoke_device" }

func (c RevokeDevice) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	res, err := tx.ExecContext(ctx,
		`UPDATE certs SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL`, c.Now, c.DeviceID)
	if err != nil {
		return Result{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Result{}, err
	}
	if n == 0 {
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM certs WHERE device_id = ?)`, c.DeviceID).Scan(&exists); err != nil {
			return Result{}, err
		}
		if !exists {
			return Result{}, ErrNotFound
		}
	}
	return Result{Count: int(n)}, nil
}

// AppendAudit appends one audit log entry. IDs are assigned in apply order,
// so every node that applies the same commands holds identical rows.
// Result: ID.
type AppendAudit struct {
	TS        int64  `json:"ts"`
	ActorKind string `json:"actor_kind"`
	ActorID   string `json:"actor_id"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Decision  string `json:"decision"`
	Result    string `json:"result"`
	Detail    string `json:"detail"`
}

// Op implements Command.
func (AppendAudit) Op() string { return "append_audit" }

// auditInsertSQL is the insert before auditOpSchema; auditInsertIndexedSQL
// sets the operation columns from the detail, as audit.go describes. The
// detail is the last parameter, selected from a one-row subquery to be read
// by both the column and the expressions.
const (
	auditInsertSQL = `
		INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	auditInsertIndexedSQL = `
		INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, detail, audit_op, audit_outcome_of)
		SELECT ?, ?, ?, ?, ?, ?, ?, detail,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_op') END,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END
		FROM (SELECT ? AS detail)`
)

func (c AppendAudit) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	// The operation columns come from the detail here, so the command is the
	// same on every binary. A node still before auditOpSchema has no columns.
	v, err := schemaVersion(ctx, tx)
	if err != nil {
		return Result{}, err
	}
	insert := auditInsertSQL
	if v >= auditOpSchema {
		insert = auditInsertIndexedSQL
	}
	res, err := tx.ExecContext(ctx, insert,
		c.TS, c.ActorKind, c.ActorID, c.Action, c.Target, c.Decision, c.Result, c.Detail)
	if err != nil {
		return Result{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Result{}, err
	}
	return Result{ID: id}, nil
}

// AppendAuditOnce is AppendAudit for an entry that may be written more than
// once, such as one retried after a write that seemed to fail: an entry
// whose Key is in the log already is not appended again, and its ID is the
// result. An empty Key appends as AppendAudit does. Result: ID.
type AppendAuditOnce struct {
	AppendAudit
	Key string `json:"key"`
}

// Op implements Command.
func (AppendAuditOnce) Op() string { return "append_audit_once" }

func (AppendAuditOnce) minSchema() int64 { return auditKeySchema }

// auditInsertKeyedSQL is auditInsertIndexedSQL setting the key too, the last
// parameter.
const auditInsertKeyedSQL = `
	INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, detail, audit_op, audit_outcome_of, audit_key)
	SELECT ?, ?, ?, ?, ?, ?, ?, detail,
	       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_op') END,
	       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END,
	       nullif(k, '')
	FROM (SELECT ? AS detail, ? AS k)`

func (c AppendAuditOnce) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM audit_log WHERE audit_key = ?`, c.Key).Scan(&id)
	if err == nil {
		return Result{ID: id}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Result{}, err
	}
	res, err := tx.ExecContext(ctx, auditInsertKeyedSQL,
		c.TS, c.ActorKind, c.ActorID, c.Action, c.Target, c.Decision, c.Result, c.Detail, c.Key)
	if err != nil {
		return Result{}, err
	}
	if id, err = res.LastInsertId(); err != nil {
		return Result{}, err
	}
	return Result{ID: id}, nil
}

// SetPasswordHash sets the admin password hash and ends every session.
type SetPasswordHash struct {
	Hash string `json:"hash"`
}

// Op implements Command.
func (SetPasswordHash) Op() string { return "set_password_hash" }

func (c SetPasswordHash) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO admin (id, password_hash) VALUES (1, ?)
		ON CONFLICT (id) DO UPDATE SET password_hash = excluded.password_hash`, c.Hash); err != nil {
		return Result{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return Result{}, fmt.Errorf("end sessions: %w", err)
	}
	return Result{}, nil
}

// CreateSession prunes sessions expired at Now and stores a new one by its
// SHA-256 hash.
type CreateSession struct {
	Hash      []byte `json:"hash"`
	Now       int64  `json:"now"`
	ExpiresAt int64  `json:"expires_at"`
}

// Op implements Command.
func (CreateSession) Op() string { return "create_session" }

func (c CreateSession) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, c.Now); err != nil {
		return Result{}, fmt.Errorf("prune: %w", err)
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO sessions (hash, created_at, expires_at) VALUES (?, ?, ?)`, c.Hash, c.Now, c.ExpiresAt)
	return Result{}, err
}

// DeleteSession ends a session; an unknown session is not an error.
type DeleteSession struct {
	Hash []byte `json:"hash"`
}

// Op implements Command.
func (DeleteSession) Op() string { return "delete_session" }

func (c DeleteSession) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, c.Hash)
	return Result{}, err
}

func nullInt(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

// commandVersion is the encoding version written by EncodeCommand. Bump it
// (and keep decoding the old one) when a command's fields change meaning.
const commandVersion = 1

type envelope struct {
	V   int             `json:"v"`
	Op  string          `json:"op"`
	Cmd json.RawMessage `json:"cmd"`
}

// EncodeCommand serializes cmd for a replicated log.
func EncodeCommand(cmd Command) ([]byte, error) {
	body, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("encode command %s: %w", cmd.Op(), err)
	}
	b, err := json.Marshal(envelope{V: commandVersion, Op: cmd.Op(), Cmd: body})
	if err != nil {
		return nil, fmt.Errorf("encode command %s: %w", cmd.Op(), err)
	}
	return b, nil
}

// DecodeCommand parses a command written by EncodeCommand. Unknown versions,
// ops and fields are errors: a node must never silently drop part of a write
// that other nodes applied in full.
func DecodeCommand(b []byte) (Command, error) {
	var env envelope
	if err := strictUnmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("decode command: %w", err)
	}
	if env.V != commandVersion {
		return nil, fmt.Errorf("decode command %s: unsupported version %d", env.Op, env.V)
	}
	var (
		cmd Command
		err error
	)
	switch env.Op {
	case UpsertDevice{}.Op():
		cmd, err = decodeAs[UpsertDevice](env.Cmd)
	case ReportFacts{}.Op():
		cmd, err = decodeAs[ReportFacts](env.Cmd)
	case MarkSeen{}.Op():
		cmd, err = decodeAs[MarkSeen](env.Cmd)
	case SetBootTime{}.Op():
		cmd, err = decodeAs[SetBootTime](env.Cmd)
	case MarkOffline{}.Op():
		cmd, err = decodeAs[MarkOffline](env.Cmd)
	case MarkSeenBatch{}.Op():
		cmd, err = decodeAs[MarkSeenBatch](env.Cmd)
	case MarkDevicesOffline{}.Op():
		cmd, err = decodeAs[MarkDevicesOffline](env.Cmd)
	case SetHubURL{}.Op():
		cmd, err = decodeAs[SetHubURL](env.Cmd)
	case RecordHubCert{}.Op():
		cmd, err = decodeAs[RecordHubCert](env.Cmd)
	case RevokeHubCerts{}.Op():
		cmd, err = decodeAs[RevokeHubCerts](env.Cmd)
	case PinCert{}.Op():
		cmd, err = decodeAs[PinCert](env.Cmd)
	case CreateToken{}.Op():
		cmd, err = decodeAs[CreateToken](env.Cmd)
	case ConsumeToken{}.Op():
		cmd, err = decodeAs[ConsumeToken](env.Cmd)
	case CreateJoinToken{}.Op():
		cmd, err = decodeAs[CreateJoinToken](env.Cmd)
	case ConsumeJoinToken{}.Op():
		cmd, err = decodeAs[ConsumeJoinToken](env.Cmd)
	case CreateCert{}.Op():
		cmd, err = decodeAs[CreateCert](env.Cmd)
	case RevokeDevice{}.Op():
		cmd, err = decodeAs[RevokeDevice](env.Cmd)
	case AppendAudit{}.Op():
		cmd, err = decodeAs[AppendAudit](env.Cmd)
	case AppendAuditOnce{}.Op():
		cmd, err = decodeAs[AppendAuditOnce](env.Cmd)
	case SetPasswordHash{}.Op():
		cmd, err = decodeAs[SetPasswordHash](env.Cmd)
	case CreateSession{}.Op():
		cmd, err = decodeAs[CreateSession](env.Cmd)
	case DeleteSession{}.Op():
		cmd, err = decodeAs[DeleteSession](env.Cmd)
	case MigrateSchema{}.Op():
		cmd, err = decodeAs[MigrateSchema](env.Cmd)
	case RecordAutomationRun{}.Op():
		cmd, err = decodeAs[RecordAutomationRun](env.Cmd)
	case AddKubeCluster{}.Op():
		cmd, err = decodeAs[AddKubeCluster](env.Cmd)
	case RemoveKubeCluster{}.Op():
		cmd, err = decodeAs[RemoveKubeCluster](env.Cmd)
	case AddProxmoxServer{}.Op():
		cmd, err = decodeAs[AddProxmoxServer](env.Cmd)
	case RemoveProxmoxServer{}.Op():
		cmd, err = decodeAs[RemoveProxmoxServer](env.Cmd)
	case CreateApproval{}.Op():
		cmd, err = decodeAs[CreateApproval](env.Cmd)
	case DecideApproval{}.Op():
		cmd, err = decodeAs[DecideApproval](env.Cmd)
	case CreateApprovalLink{}.Op():
		cmd, err = decodeAs[CreateApprovalLink](env.Cmd)
	case UseApprovalLink{}.Op():
		cmd, err = decodeAs[UseApprovalLink](env.Cmd)
	case CreateMCPToken{}.Op():
		cmd, err = decodeAs[CreateMCPToken](env.Cmd)
	case RevokeMCPToken{}.Op():
		cmd, err = decodeAs[RevokeMCPToken](env.Cmd)
	case RecordNetworkScan{}.Op():
		cmd, err = decodeAs[RecordNetworkScan](env.Cmd)
	case SetNetworkHostState{}.Op():
		cmd, err = decodeAs[SetNetworkHostState](env.Cmd)
	case RecordNetworkImport{}.Op():
		cmd, err = decodeAs[RecordNetworkImport](env.Cmd)
	case CreateRunbookRun{}.Op():
		cmd, err = decodeAs[CreateRunbookRun](env.Cmd)
	case SaveRunbookRun{}.Op():
		cmd, err = decodeAs[SaveRunbookRun](env.Cmd)
	case SetTelemetry{}.Op():
		cmd, err = decodeAs[SetTelemetry](env.Cmd)
	case MarkTelemetrySent{}.Op():
		cmd, err = decodeAs[MarkTelemetrySent](env.Cmd)
	case CreatePanel{}.Op():
		cmd, err = decodeAs[CreatePanel](env.Cmd)
	case UpdatePanel{}.Op():
		cmd, err = decodeAs[UpdatePanel](env.Cmd)
	case DeletePanel{}.Op():
		cmd, err = decodeAs[DeletePanel](env.Cmd)
	case CreatePanelLink{}.Op():
		cmd, err = decodeAs[CreatePanelLink](env.Cmd)
	case RevokePanelLink{}.Op():
		cmd, err = decodeAs[RevokePanelLink](env.Cmd)
	case CreateDashboardToken{}.Op():
		cmd, err = decodeAs[CreateDashboardToken](env.Cmd)
	case RevokeDashboardToken{}.Op():
		cmd, err = decodeAs[RevokeDashboardToken](env.Cmd)
	default:
		return nil, fmt.Errorf("decode command: unknown op %q", env.Op)
	}
	if err != nil {
		return nil, fmt.Errorf("decode command %s: %w", env.Op, err)
	}
	return cmd, nil
}

func decodeAs[T Command](b []byte) (Command, error) {
	var c T
	if err := strictUnmarshal(b, &c); err != nil {
		return nil, err
	}
	return c, nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
