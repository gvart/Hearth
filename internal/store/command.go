// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Command is a typed, serializable description of one store write. It carries
// its inputs (timestamps, hashes, encoded JSON, and the Stamp that versions
// its rows), so a member can forward it to the replica that runs it. Commands
// are built by the repository methods; the set is closed to this package.
//
// Timestamps are unix milliseconds (UTC), matching the schema. JSON documents
// (facts, labels, detail) are carried as strings so they are stored byte for
// byte as the caller passed them, whether applied directly or after a round
// trip through EncodeCommand.
type Command interface {
	// Op is the command's stable name in its encoded form.
	Op() string
	// apply executes the command: it reads rows and writes the rows it
	// changes, whole, through w (see version.go).
	apply(ctx context.Context, w *writer) (Result, error)
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
	// Name is the device name of the token consumed by ConsumeToken, or "".
	Name string
	// ApprovalID is the approval of the link spent by UseApprovalLink.
	ApprovalID string
	// ID is the audit_log ID assigned by AppendAudit.
	ID int64
	// Count is the number of certificates revoked by RevokeDevice or
	// RevokeHubCerts, or of hosts recorded by RecordNetworkScan.
	Count int
	// NewHosts and ReturnedHosts are the hosts RecordNetworkScan found for
	// the first time, and back after an absence.
	NewHosts      []NetworkHost
	ReturnedHosts []NetworkHost
	// PinMismatch is true when PinCert recorded a mismatch.
	PinMismatch bool
	// Roles are the cluster roles of the join token consumed by
	// ConsumeJoinToken, comma-separated.
	Roles string
	// DeviceID is the device the join token consumed by ConsumeJoinToken
	// was minted for, or "".
	DeviceID string
	// HubRoles are the hub roles of the token consumed by ConsumeToken.
	HubRoles string
}

// UpsertDevice inserts a device or replaces every field but first_seen.
type UpsertDevice struct {
	Stamp
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

func (c UpsertDevice) apply(ctx context.Context, w *writer) (Result, error) {
	r, err := w.get(ctx, "devices", c.ID)
	if err != nil {
		return Result{}, err
	}
	if r == nil {
		r = row{"id": c.ID, "first_seen": c.FirstSeen}
	}
	r["name"], r["hostname"], r["os"], r["arch"] = c.Name, c.Hostname, c.OS, c.Arch
	r["facts"], r["labels"], r["last_seen"], r["status"] = c.Facts, c.Labels, c.LastSeen, c.Status
	r["boot_time"] = optInt(c.BootTime)
	return Result{}, w.put(ctx, "devices", r)
}

// ReportFacts records facts reported by a device and marks it online.
// Result: Device, PrevStatus.
type ReportFacts struct {
	Stamp
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Facts    string `json:"facts"`
	Now      int64  `json:"now"`
}

// Op implements Command.
func (ReportFacts) Op() string { return "report_facts" }

func (c ReportFacts) apply(ctx context.Context, w *writer) (Result, error) {
	return updateDevice(ctx, w, c.ID, func(r row) {
		r["hostname"], r["os"], r["arch"], r["facts"] = c.Hostname, c.OS, c.Arch, c.Facts
		r["last_seen"], r["status"] = c.Now, StatusOnline
	})
}

// MarkSeen sets a device's last_seen and marks it online.
// Result: Device, PrevStatus.
type MarkSeen struct {
	Stamp
	ID  string `json:"id"`
	Now int64  `json:"now"`
}

// Op implements Command.
func (MarkSeen) Op() string { return "mark_seen" }

func (c MarkSeen) apply(ctx context.Context, w *writer) (Result, error) {
	return updateDevice(ctx, w, c.ID, func(r row) {
		r["last_seen"], r["status"] = c.Now, StatusOnline
	})
}

// updateDevice applies set to device id and returns the updated row and the
// status it had before, or ErrNotFound.
func updateDevice(ctx context.Context, w *writer, id string, set func(r row)) (Result, error) {
	r, err := w.get(ctx, "devices", id)
	if err != nil {
		return Result{}, err
	}
	if r == nil {
		return Result{}, ErrNotFound
	}
	prev := r.str("status")
	set(r)
	if err := w.put(ctx, "devices", r); err != nil {
		return Result{}, err
	}
	d, err := deviceOf(r)
	if err != nil {
		return Result{}, err
	}
	return Result{Device: d, PrevStatus: prev}, nil
}

// deviceOf decodes a devices row.
func deviceOf(r row) (Device, error) {
	return scanDevice(r.scanner(deviceColumnList...))
}

var deviceColumnList = strings.Split(deviceColumns, ", ")

// SetBootTime sets or clears a device's boot time. Result: Device.
type SetBootTime struct {
	Stamp
	ID string `json:"id"`
	// BootTime is nil to clear it.
	BootTime *int64 `json:"boot_time,omitempty"`
}

// Op implements Command.
func (SetBootTime) Op() string { return "set_boot_time" }

func (c SetBootTime) apply(ctx context.Context, w *writer) (Result, error) {
	res, err := updateDevice(ctx, w, c.ID, func(r row) { r["boot_time"] = optInt(c.BootTime) })
	res.PrevStatus = ""
	return res, err
}

// MarkOffline marks every online device last seen before Cutoff as offline.
// Result: Devices.
type MarkOffline struct {
	Stamp
	Cutoff int64 `json:"cutoff"`
}

// Op implements Command.
func (MarkOffline) Op() string { return "mark_offline" }

func (c MarkOffline) apply(ctx context.Context, w *writer) (Result, error) {
	rows, err := w.query(ctx, "devices", `status = '`+StatusOnline+`' AND last_seen < ?`, "id", c.Cutoff)
	if err != nil {
		return Result{}, err
	}
	return markOffline(ctx, w, rows)
}

// markOffline marks the devices rows offline and returns them, in order.
func markOffline(ctx context.Context, w *writer, rows []row) (Result, error) {
	var out []Device
	for _, r := range rows {
		r["status"] = StatusOffline
		if err := w.put(ctx, "devices", r); err != nil {
			return Result{}, err
		}
		d, err := deviceOf(r)
		if err != nil {
			return Result{}, err
		}
		out = append(out, d)
	}
	return Result{Devices: out}, nil
}

// MarkDevicesOffline marks the listed devices offline if they are online: a
// master names the devices whose presence it owns, rather than comparing
// every stored last_seen with a cutoff as MarkOffline does. Result: Devices,
// the rows changed, ordered by ID.
type MarkDevicesOffline struct {
	Stamp
	IDs []string `json:"ids"`
	// Cutoff, when set, spares a device last seen at or after it (Unix ms):
	// a master sweeping devices whose stream is elsewhere must not mark one
	// offline on a stale read.
	Cutoff int64 `json:"cutoff,omitempty"`
}

// Op implements Command.
func (MarkDevicesOffline) Op() string { return "mark_devices_offline" }

func (c MarkDevicesOffline) apply(ctx context.Context, w *writer) (Result, error) {
	ids := map[string]bool{}
	for _, id := range c.IDs {
		ids[id] = true
	}
	var online []row
	for id := range ids {
		r, err := w.get(ctx, "devices", id)
		if err != nil {
			return Result{}, err
		}
		if r != nil && r.str("status") == StatusOnline && (c.Cutoff == 0 || r.int("last_seen") < c.Cutoff) {
			online = append(online, r)
		}
	}
	sortRows(online, "id")
	return markOffline(ctx, w, online)
}

// SetHubURL records the agent-facing URL of a cluster hub. Each hub writes
// its own row when it starts; agents are sent these URLs to fail over to.
type SetHubURL struct {
	Stamp
	NodeID   string `json:"node_id"`
	AgentURL string `json:"agent_url"`
}

// Op implements Command.
func (SetHubURL) Op() string { return "set_hub_url" }

func (c SetHubURL) apply(ctx context.Context, w *writer) (Result, error) {
	r, err := w.get(ctx, "cluster_hubs", c.NodeID)
	if err != nil {
		return Result{}, err
	}
	if r == nil {
		r = row{"node_id": c.NodeID}
	}
	r["agent_url"] = c.AgentURL
	return Result{}, w.put(ctx, "cluster_hubs", r)
}

// RecordHubCert records a hub node certificate issued to a cluster node.
// Recording a known serial again is a no-op: it never clears a revocation.
//
// From CertPinsSchema it also records the certificate's Fingerprint and the
// fingerprint of the CA that issued it (CAFP), and fills them in for a known
// serial of the same node recorded without them. Below that schema they are
// dropped.
type RecordHubCert struct {
	Stamp
	Serial      string `json:"serial"`
	NodeID      string `json:"node_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
	CAFP        string `json:"ca_fp,omitempty"`
}

// Op implements Command.
func (RecordHubCert) Op() string { return "record_hub_cert" }

func (RecordHubCert) minSchema() int64 { return hubCertsSchema }

func (c RecordHubCert) apply(ctx context.Context, w *writer) (Result, error) {
	pinned := w.schema >= CertPinsSchema
	r, err := w.get(ctx, "hub_certs", c.Serial)
	if err != nil {
		return Result{}, err
	}
	if r == nil {
		r = row{"serial": c.Serial, "node_id": c.NodeID, "revoked_at": nil}
		if pinned {
			r["fingerprint"], r["ca_fp"] = optString(c.Fingerprint), optString(c.CAFP)
		}
		return Result{}, w.put(ctx, "hub_certs", r)
	}
	// A known serial keeps its node ID and revocation; only a missing
	// fingerprint is filled in.
	if !pinned || r.str("node_id") != c.NodeID {
		return Result{}, nil
	}
	changed := false
	for col, v := range map[string]string{"fingerprint": c.Fingerprint, "ca_fp": c.CAFP} {
		if r.isNull(col) && v != "" {
			r[col], changed = v, true
		}
	}
	if !changed {
		return Result{}, nil
	}
	return Result{}, w.put(ctx, "hub_certs", r)
}

// RevokeHubCerts revokes every unrevoked hub certificate recorded for a node
// at Now. Result: Count, which is zero when there was nothing to revoke.
type RevokeHubCerts struct {
	Stamp
	NodeID string `json:"node_id"`
	Now    int64  `json:"now"`
}

// Op implements Command.
func (RevokeHubCerts) Op() string { return "revoke_hub_certs" }

func (RevokeHubCerts) minSchema() int64 { return hubCertsSchema }

func (c RevokeHubCerts) apply(ctx context.Context, w *writer) (Result, error) {
	n, err := revokeWhere(ctx, w, "hub_certs", `node_id = ?`, c.Now, c.NodeID)
	return Result{Count: n}, err
}

// revokeWhere sets revoked_at to now on the unrevoked rows of table matching
// where, and returns how many it revoked.
func revokeWhere(ctx context.Context, w *writer, table, where string, now int64, args ...any) (int, error) {
	rows, err := w.query(ctx, table, where+` AND revoked_at IS NULL`, tables[table].pk[0], args...)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		r["revoked_at"] = now
		if err := w.put(ctx, table, r); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// CreateToken stores a single-use enrollment token by its SHA-256 hash.
type CreateToken struct {
	Stamp
	Hash      []byte `json:"hash"`
	Labels    string `json:"labels"`
	ExpiresAt int64  `json:"expires_at"`
	// Name is the device name the token gives, or "" for the agent's
	// hostname. A named token needs tokenNameSchema.
	Name string `json:"name,omitempty"`
	// HubRoles are the cluster roles the device may be offered,
	// comma-separated, or "" for none. Hub roles need hubTokenSchema.
	HubRoles string `json:"hub_roles,omitempty"`
	// Owner is the master that owns the token in an AP cluster (OwnedBy).
	Owner string `json:"owner,omitempty"`
}

// Op implements Command.
func (CreateToken) Op() string { return "create_token" }

func (c CreateToken) minSchema() int64 {
	if c.HubRoles != "" {
		return ownedSchema(c.Owner, hubTokenSchema)
	}
	if c.Name != "" {
		return ownedSchema(c.Owner, tokenNameSchema)
	}
	return ownedSchema(c.Owner, 0)
}

func (c CreateToken) apply(ctx context.Context, w *writer) (Result, error) {
	r := row{"hash": c.Hash, "labels": c.Labels, "expires_at": c.ExpiresAt, "used_at": nil}
	if w.schema >= tokenNameSchema {
		r["name"] = c.Name
	}
	if w.schema >= hubTokenSchema {
		r["hub_roles"] = c.HubRoles
	}
	return Result{}, w.insert(ctx, "tokens", withOwner(r, c.Owner))
}

// ConsumeToken marks a token used at Now if it is unused and unexpired. The
// outcome is decided inside apply, so exactly one ConsumeToken per token wins
// however often the log is replayed. Result: Labels, Name. It fails with
// ErrNotFound, ErrTokenUsed or ErrTokenExpired.
type ConsumeToken struct {
	Stamp
	Hash []byte `json:"hash"`
	Now  int64  `json:"now"`
	// Master is the master consuming it in an AP cluster (OwnedBy).
	Master string `json:"master,omitempty"`
}

// Op implements Command.
func (ConsumeToken) Op() string { return "consume_token" }

func (c ConsumeToken) minSchema() int64 { return ownedSchema(c.Master, 0) }

func (c ConsumeToken) apply(ctx context.Context, w *writer) (Result, error) {
	r, err := consume(ctx, w, "tokens", "token", c.Hash, c.Now, c.Master, nil)
	if err != nil {
		return Result{}, err
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(r.str("labels")), &out); err != nil {
		return Result{}, fmt.Errorf("decode labels: %w", err)
	}
	return Result{Labels: out, Name: r.str("name"), HubRoles: r.str("hub_roles")}, nil
}

// consume marks the single-use secret with hash in table (tokens,
// join_tokens or approval_links) used at now, and returns its row. It fails
// with ErrNotFound, a *NotOwnerError when master does not own it (what names
// it), ErrTokenUsed or ErrTokenExpired, in that order.
func consume(ctx context.Context, w *writer, table, what string, hash []byte, now int64, master string, set row) (row, error) {
	r, err := w.get(ctx, table, hash)
	if err == nil && r != nil {
		err = checkOwner(r, what, master)
	}
	switch {
	case err != nil:
		return nil, err
	case r == nil:
		return nil, ErrNotFound
	case !r.isNull("used_at"):
		return nil, ErrTokenUsed
	case r.int("expires_at") <= now:
		return nil, ErrTokenExpired
	}
	r["used_at"] = now
	for k, v := range set {
		r[k] = v
	}
	return r, w.put(ctx, table, r)
}

// CreateJoinToken stores a single-use cluster join token by its SHA-256 hash.
type CreateJoinToken struct {
	Stamp
	Hash      []byte `json:"hash"`
	ExpiresAt int64  `json:"expires_at"`
	// Roles are the cluster roles the token grants, comma-separated.
	Roles string `json:"roles"`
	// DeviceID is the device the token was minted for at its enrollment
	// (#328), or "" for a token an admin created. It needs hubTokenSchema.
	DeviceID string `json:"device_id,omitempty"`
	// Owner is the master that owns the token in an AP cluster (OwnedBy).
	Owner string `json:"owner,omitempty"`
}

// Op implements Command.
func (CreateJoinToken) Op() string { return "create_join_token" }

func (c CreateJoinToken) minSchema() int64 {
	if c.DeviceID != "" {
		return ownedSchema(c.Owner, hubTokenSchema)
	}
	return ownedSchema(c.Owner, joinTokenRolesSchema)
}

func (c CreateJoinToken) apply(ctx context.Context, w *writer) (Result, error) {
	r := row{"hash": c.Hash, "expires_at": c.ExpiresAt, "used_at": nil, "roles": c.Roles}
	if w.schema >= hubTokenSchema {
		r["device_id"] = c.DeviceID
	}
	return Result{}, w.insert(ctx, "join_tokens", withOwner(r, c.Owner))
}

// ConsumeJoinToken marks a join token used at Now if it is unused and
// unexpired, deciding inside apply like ConsumeToken, and returns its Roles.
// It fails with ErrNotFound, ErrTokenUsed or ErrTokenExpired.
type ConsumeJoinToken struct {
	Stamp
	Hash []byte `json:"hash"`
	Now  int64  `json:"now"`
	// Master is the master consuming it in an AP cluster (OwnedBy).
	Master string `json:"master,omitempty"`
	// NodeID is the hub joining with it, kept on a token minted for a
	// device (#328) from hubTokenSchema.
	NodeID string `json:"node_id,omitempty"`
}

// Op implements Command.
func (ConsumeJoinToken) Op() string { return "consume_join_token" }

func (c ConsumeJoinToken) minSchema() int64 { return ownedSchema(c.Master, joinTokenRolesSchema) }

func (c ConsumeJoinToken) apply(ctx context.Context, w *writer) (Result, error) {
	var set row
	if w.schema >= hubTokenSchema {
		set = row{"joined_node": c.NodeID}
	}
	r, err := consume(ctx, w, "join_tokens", "join token", c.Hash, c.Now, c.Master, set)
	if err != nil {
		return Result{}, err
	}
	return Result{Roles: r.str("roles"), DeviceID: r.str("device_id")}, nil
}

// CreateCert records a certificate issued to a device. From CertPinsSchema it also
// records the certificate's Fingerprint and the fingerprint of the CA that
// issued it (CAFP); below that schema they are dropped, the same way on every
// node.
type CreateCert struct {
	Stamp
	Serial      string `json:"serial"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
	CAFP        string `json:"ca_fp,omitempty"`
}

// Op implements Command.
func (CreateCert) Op() string { return "create_cert" }

func (c CreateCert) apply(ctx context.Context, w *writer) (Result, error) {
	r := row{"serial": c.Serial, "device_id": c.DeviceID, "revoked_at": nil}
	if w.schema >= CertPinsSchema {
		r["fingerprint"], r["ca_fp"], r["pin_mismatch_at"] = optString(c.Fingerprint), optString(c.CAFP), nil
	}
	return Result{}, w.insert(ctx, "certs", r)
}

// RevokeDevice revokes every unrevoked certificate of a device at Now.
// Result: Count. It fails with ErrNotFound if the device has no certificates.
type RevokeDevice struct {
	Stamp
	DeviceID string `json:"device_id"`
	Now      int64  `json:"now"`
}

// Op implements Command.
func (RevokeDevice) Op() string { return "revoke_device" }

func (c RevokeDevice) apply(ctx context.Context, w *writer) (Result, error) {
	n, err := revokeWhere(ctx, w, "certs", `device_id = ?`, c.Now, c.DeviceID)
	if err != nil {
		return Result{}, err
	}
	if n == 0 {
		all, err := w.query(ctx, "certs", `device_id = ?`, "", c.DeviceID)
		if err != nil {
			return Result{}, err
		}
		if len(all) == 0 {
			return Result{}, ErrNotFound
		}
	}
	return Result{Count: n}, nil
}

// AppendAudit appends one audit log entry. Result: ID, its row id in this
// member's database; across the cluster an entry is known by its version
// (_hlc, _origin, _seq).
type AppendAudit struct {
	Stamp
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

func (c AppendAudit) apply(ctx context.Context, w *writer) (Result, error) {
	id, err := w.appendAudit(ctx, c, "")
	return Result{ID: id}, err
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

func (c AppendAuditOnce) apply(ctx context.Context, w *writer) (Result, error) {
	var id int64
	err := w.tx.QueryRowContext(ctx, `SELECT id FROM audit_log WHERE audit_key = ?`, c.Key).Scan(&id)
	if err == nil {
		return Result{ID: id}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Result{}, err
	}
	id, err = w.appendAudit(ctx, c.AppendAudit, c.Key)
	return Result{ID: id}, err
}

// SetPasswordHash sets the admin password hash and ends every session: it
// deletes those here, and raises the session epoch past Now, the reset's
// time, which ends on every master those it misses (#384).
type SetPasswordHash struct {
	Stamp
	Hash string `json:"hash"`
	Now  int64  `json:"now"`
}

// Op implements Command.
func (SetPasswordHash) Op() string { return "set_password_hash" }

func (c SetPasswordHash) apply(ctx context.Context, w *writer) (Result, error) {
	admin := row{"id": int64(1), "password_hash": c.Hash}
	if w.schema >= sessionEpochSchema {
		epoch, err := sessionEpoch(ctx, w)
		if err != nil {
			return Result{}, err
		}
		// Past the one before, whatever this master's clock says.
		admin["session_epoch"] = max(c.Now, epoch+1)
	}
	if err := w.put(ctx, "admin", admin); err != nil {
		return Result{}, err
	}
	if err := deleteWhere(ctx, w, "sessions", `1 = 1`); err != nil {
		return Result{}, fmt.Errorf("end sessions: %w", err)
	}
	return Result{}, nil
}

// deleteWhere deletes the live rows of table matching where.
func deleteWhere(ctx context.Context, w *writer, table, where string, args ...any) error {
	rows, err := w.query(ctx, table, where, tables[table].pk[0], args...)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := w.delete(ctx, table, r); err != nil {
			return err
		}
	}
	return nil
}

// CreateSession prunes sessions expired at Now and stores a new one by its
// SHA-256 hash.
type CreateSession struct {
	Stamp
	Hash      []byte `json:"hash"`
	Now       int64  `json:"now"`
	ExpiresAt int64  `json:"expires_at"`
}

// Op implements Command.
func (CreateSession) Op() string { return "create_session" }

func (c CreateSession) apply(ctx context.Context, w *writer) (Result, error) {
	if err := deleteWhere(ctx, w, "sessions", `expires_at <= ?`, c.Now); err != nil {
		return Result{}, fmt.Errorf("prune: %w", err)
	}
	r := row{"hash": c.Hash, "created_at": c.Now, "expires_at": c.ExpiresAt}
	if w.schema >= sessionEpochSchema {
		// The epoch it is created under: a reset this master has not seen
		// yet ends it once it has.
		epoch, err := sessionEpoch(ctx, w)
		if err != nil {
			return Result{}, err
		}
		r["epoch"] = epoch
	}
	return Result{}, w.insert(ctx, "sessions", r)
}

// sessionEpochSchema is the schema version whose migration (00041) added
// the session epochs.
const sessionEpochSchema = 41

// sessionEpoch is the admin row's session epoch, 0 without one.
func sessionEpoch(ctx context.Context, w *writer) (int64, error) {
	a, err := w.get(ctx, "admin", int64(1))
	if err != nil || a == nil {
		return 0, err
	}
	e, _ := a["session_epoch"].(int64)
	return e, nil
}

// DeleteSession ends a session; an unknown session is not an error.
type DeleteSession struct {
	Stamp
	Hash []byte `json:"hash"`
}

// Op implements Command.
func (DeleteSession) Op() string { return "delete_session" }

func (c DeleteSession) apply(ctx context.Context, w *writer) (Result, error) {
	r, err := w.getAny(ctx, "sessions", c.Hash)
	switch {
	case err != nil:
		return Result{}, err
	case r == nil && w.versioned:
		// A master that does not hold it writes its tombstone all the same:
		// another master may (#384).
		return Result{}, w.write(ctx, "sessions", row{"hash": c.Hash, "created_at": int64(0), "expires_at": int64(0)}, nil, true)
	case r == nil || r.deleted():
		return Result{}, nil
	}
	return Result{}, w.delete(ctx, "sessions", r)
}

// optInt is v as a column value: NULL for nil.
func optInt(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// optString is s as a column value: NULL for "".
func optString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

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
	case StartCARotation{}.Op():
		cmd, err = decodeAs[StartCARotation](env.Cmd)
	case AdvanceCARotation{}.Op():
		cmd, err = decodeAs[AdvanceCARotation](env.Cmd)
	case ResealSecrets{}.Op():
		cmd, err = decodeAs[ResealSecrets](env.Cmd)
	case RevokeCACerts{}.Op():
		cmd, err = decodeAs[RevokeCACerts](env.Cmd)
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
	case PutConfigDocs{}.Op():
		cmd, err = decodeAs[PutConfigDocs](env.Cmd)
	case DeleteConfigDoc{}.Op():
		cmd, err = decodeAs[DeleteConfigDoc](env.Cmd)
	case SetDeviceCeiling{}.Op():
		cmd, err = decodeAs[SetDeviceCeiling](env.Cmd)
	case AddESPHomeDevice{}.Op():
		cmd, err = decodeAs[AddESPHomeDevice](env.Cmd)
	case RemoveESPHomeDevice{}.Op():
		cmd, err = decodeAs[RemoveESPHomeDevice](env.Cmd)
	case AddOpenWrtRouter{}.Op():
		cmd, err = decodeAs[AddOpenWrtRouter](env.Cmd)
	case RemoveOpenWrtRouter{}.Op():
		cmd, err = decodeAs[RemoveOpenWrtRouter](env.Cmd)
	case AddOPNsenseFirewall{}.Op():
		cmd, err = decodeAs[AddOPNsenseFirewall](env.Cmd)
	case RemoveOPNsenseFirewall{}.Op():
		cmd, err = decodeAs[RemoveOPNsenseFirewall](env.Cmd)
	case AddUniFiController{}.Op():
		cmd, err = decodeAs[AddUniFiController](env.Cmd)
	case RemoveUniFiController{}.Op():
		cmd, err = decodeAs[RemoveUniFiController](env.Cmd)
	case SetDevicePlugin{}.Op():
		cmd, err = decodeAs[SetDevicePlugin](env.Cmd)
	case RemoveDevicePlugin{}.Op():
		cmd, err = decodeAs[RemoveDevicePlugin](env.Cmd)
	case SetDeviceRoute{}.Op():
		cmd, err = decodeAs[SetDeviceRoute](env.Cmd)
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
