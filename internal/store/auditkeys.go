// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// auditChainSchema is the schema version whose migration (00044) added the
// audit log's seals, this member's chain heads and the audit_keys table.
const auditChainSchema = 44

// SealedAuditKey is the audit MAC key of a hub CA generation, sealed with a
// key derived from the hub CA key the masters hold (see the hub's sealers).
type SealedAuditKey struct {
	// ID is the key id entries name (chain_kid).
	ID     string
	Sealed []byte
}

// AuditKeys is the repository of the sealed audit MAC keys: a master table
// (#387), so a storage-only member neither holds nor serves them.
type AuditKeys struct{ s *Store }

// AuditKeys returns the sealed audit MAC keys repository.
func (s *Store) AuditKeys() AuditKeys { return AuditKeys{s: s} }

// List returns every sealed audit key: none below schema 44.
func (r AuditKeys) List(ctx context.Context) ([]SealedAuditKey, error) {
	if ok, err := atSchema(ctx, r.s.db, auditChainSchema); err != nil || !ok {
		return nil, err
	}
	rows, err := r.s.list(ctx, "", gather{table: "audit_keys"}, `SELECT id, sealed`, ` FROM audit_keys WHERE _deleted = 0 ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list audit keys: %w", err)
	}
	defer rows.Close()
	var out []SealedAuditKey
	for rows.Next() {
		var k SealedAuditKey
		if err := rows.Scan(&k.ID, &k.Sealed); err != nil {
			return nil, fmt.Errorf("list audit keys: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Put stores the sealed audit key id, unless one with that id is stored.
func (r AuditKeys) Put(ctx context.Context, id string, sealed []byte, now time.Time) error {
	if _, err := r.s.apply(ctx, PutAuditKey{ID: id, Sealed: sealed, CreatedAt: toMillis(now)}); err != nil {
		return fmt.Errorf("store audit key %s: %w", id, err)
	}
	return nil
}

// PutAuditKey stores a sealed audit MAC key, unless one with its id is
// stored: the same key sealed again is not news, and a rotation re-seals it
// with ResealSecrets.
type PutAuditKey struct {
	Stamp
	ID        string `json:"id"`
	Sealed    []byte `json:"sealed"`
	CreatedAt int64  `json:"created_at"`
}

// Op implements Command.
func (PutAuditKey) Op() string { return "put_audit_key" }

func (PutAuditKey) minSchema() int64 { return auditChainSchema }

func (c PutAuditKey) apply(ctx context.Context, w *writer) (Result, error) {
	if c.ID == "" || len(c.Sealed) == 0 {
		return Result{}, errors.New("put audit key: id and sealed key are required")
	}
	cur, err := w.get(ctx, "audit_keys", c.ID)
	if err != nil {
		return Result{}, err
	}
	if cur != nil {
		return Result{}, nil
	}
	return Result{}, w.put(ctx, "audit_keys", row{"id": c.ID, "sealed": c.Sealed, "created_at": c.CreatedAt})
}
