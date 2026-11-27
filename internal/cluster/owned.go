// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/gvart/hearth/internal/store"
)

// Master-owned rows and revocations of an AP cluster
// (docs/design/ap-cluster.md §5.4, §6).
//
// An enrollment or join token, an approval and an approval link are owned
// by the master that created it (store.OwnedBy stamps it on the row). Only
// that master consumes or decides it: the row's replicas refuse another
// with a *store.NotOwnerError, whichever side of a split it is on. The
// owner also keeps the uses it made in a table of its own, outside the
// replicated store, and refuses a second use from it: "single use" then
// holds on the owner without a quorum, even if the row's replicas changed
// between two uses.
//
// The owner also keeps the command that created each row it owns (#382):
// the rows are sharded, and a storage member, one of their replicas, could
// write one naming this master as its owner, or change one. A use of a row
// this master has no record of is refused, and what a use grants (a join
// token's roles, an enrollment token's labels and hub roles, a link's
// approval) comes from the record. An approval is taken as approved only if
// this master, its owner, approved it (store.Approvals.OwnerDecision).

// usesSchema keeps the owner's uses in the hints database.
const usesSchema = `CREATE TABLE IF NOT EXISTS owned_uses (
	key TEXT PRIMARY KEY
) STRICT;
CREATE TABLE IF NOT EXISTS owned_rows (
	key TEXT PRIMARY KEY,
	cmd BLOB NOT NULL,
	decision TEXT NOT NULL DEFAULT ''
) STRICT`

// ownedUses is the owner's own record of the master-owned rows it used.
type ownedUses struct {
	mu  sync.Mutex
	db  *sql.DB // nil keeps them in memory only
	mem map[string]bool
	// rows are the created rows' records when db is nil.
	rows map[string]ownedRow
}

// ownedRow is the owner's record of a row it created.
type ownedRow struct {
	cmd      []byte
	decision string
}

func newOwnedUses(ctx context.Context, h *Hints) (*ownedUses, error) {
	u := &ownedUses{mem: map[string]bool{}, rows: map[string]ownedRow{}}
	if h == nil {
		return u, nil
	}
	if _, err := h.db.ExecContext(ctx, usesSchema); err != nil {
		return nil, fmt.Errorf("owned uses: %w", err)
	}
	u.db = h.db
	return u, nil
}

func (u *ownedUses) used(ctx context.Context, key string) (bool, error) {
	if u.mem[key] || u.db == nil {
		return u.mem[key], nil
	}
	var n int
	if err := u.db.QueryRowContext(ctx, `SELECT count(*) FROM owned_uses WHERE key = ?`, key).Scan(&n); err != nil {
		return false, fmt.Errorf("owned uses: %w", err)
	}
	return n > 0, nil
}

func (u *ownedUses) mark(ctx context.Context, key string) error {
	u.mem[key] = true
	if u.db == nil {
		return nil
	}
	if _, err := u.db.ExecContext(ctx, `INSERT OR IGNORE INTO owned_uses (key) VALUES (?)`, key); err != nil {
		return fmt.Errorf("owned uses: %w", err)
	}
	return nil
}

// recordCreated keeps cmd, which creates the master-owned row key here.
func (u *ownedUses) recordCreated(ctx context.Context, key string, cmd store.Command) error {
	b, err := store.EncodeCommand(cmd)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.db == nil {
		u.rows[key] = ownedRow{cmd: b}
		return nil
	}
	if _, err := u.db.ExecContext(ctx, `INSERT OR REPLACE INTO owned_rows (key, cmd) VALUES (?, ?)`, key, b); err != nil {
		return fmt.Errorf("owned rows: %w", err)
	}
	return nil
}

// created returns the command that created the master-owned row key here,
// nil if this master created none. The caller holds mu.
func (u *ownedUses) created(ctx context.Context, key string) (store.Command, error) {
	var b []byte
	if u.db == nil {
		b = u.rows[key].cmd
	} else {
		err := u.db.QueryRowContext(ctx, `SELECT cmd FROM owned_rows WHERE key = ?`, key).Scan(&b)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("owned rows: %w", err)
		}
	}
	if b == nil {
		return nil, nil
	}
	return store.DecodeCommand(b)
}

// setDecision records this master's decision on the row key. The caller
// holds mu.
func (u *ownedUses) setDecision(ctx context.Context, key, status string) error {
	if u.db == nil {
		row := u.rows[key]
		row.decision = status
		u.rows[key] = row
		return nil
	}
	if _, err := u.db.ExecContext(ctx, `UPDATE owned_rows SET decision = ? WHERE key = ?`, status, key); err != nil {
		return fmt.Errorf("owned rows: %w", err)
	}
	return nil
}

// OwnerDecision implements store.OwnerDecisions.
func (r *Replicator) OwnerDecision(ctx context.Context, id string) (string, error) {
	u := r.uses
	u.mu.Lock()
	defer u.mu.Unlock()
	key := "approvals/" + id
	if u.db == nil {
		return u.rows[key].decision, nil
	}
	var d string
	err := u.db.QueryRowContext(ctx, `SELECT decision FROM owned_rows WHERE key = ?`, key).Scan(&d)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("owned rows: %w", err)
	}
	return d, nil
}

// errNotCreatedHere refuses a use of a master-owned row that names this
// master as its owner, though this master never created it: a replica wrote
// it (#382).
var errNotCreatedHere = errors.New("this master did not create it")

// applyOwned applies cmd, a use of the master-owned row key, once: a use
// this master made before is refused without asking the replicas, and a use
// that may have taken effect is recorded even if it failed.
func (r *Replicator) applyOwned(ctx context.Context, key string, cmd store.Command) (store.Result, error) {
	u := r.uses
	u.mu.Lock()
	defer u.mu.Unlock()
	used, err := u.used(ctx, key)
	if err != nil {
		return store.Result{}, err
	}
	if used {
		if strings.HasPrefix(key, "approvals/") {
			return store.Result{}, fmt.Errorf("apply %s: %w: this master decided it already", cmd.Op(), store.ErrApprovalClosed)
		}
		return store.Result{}, fmt.Errorf("apply %s: %w", cmd.Op(), store.ErrTokenUsed)
	}
	created, err := u.created(ctx, key)
	if err != nil {
		return store.Result{}, err
	}
	if d, ok := cmd.(store.DecideApproval); ok && created != nil {
		// Before the decision can be read: the request held here waits for it.
		if err := u.setDecision(ctx, key, d.Status); err != nil {
			return store.Result{}, err
		}
	}
	res, err := r.applyRouted(ctx, cmd)
	if err == nil || mayHaveApplied(err) {
		if merr := u.mark(context.WithoutCancel(ctx), key); merr != nil {
			r.log.ErrorContext(ctx, "record a use of a master-owned row", "op", cmd.Op(), "err", merr)
		}
	}
	if err != nil {
		// Another master's row is refused by its replicas, naming its owner.
		return res, err
	}
	if created == nil {
		r.log.WarnContext(ctx, "refused a master-owned row this master did not create: a replica wrote it",
			"op", cmd.Op(), "row", strings.SplitN(key, "/", 2)[0])
		return store.Result{}, fmt.Errorf("apply %s: %w: %w", cmd.Op(), store.ErrNotFound, errNotCreatedHere)
	}
	return store.OwnedResult(created, cmd, res)
}

// mayHaveApplied reports whether a failed use may still have taken effect on
// a replica: anything but a refusal of the row itself.
func mayHaveApplied(err error) bool {
	for _, refusal := range []error{
		store.ErrNotFound, store.ErrTokenExpired, store.ErrNotOwner, store.ErrApprovalClosed,
		store.ErrSchemaTooOld, store.ErrNoRoute, store.ErrTokenUsed,
	} {
		if errors.Is(err, refusal) {
			return false
		}
	}
	return true
}

// revocationMsg tells the members that From wrote revocations: each member
// holding one of the rows fetches it from From and merges it at once,
// without waiting for anti-entropy. It names rows only, never a secret.
type revocationMsg struct {
	Kind string         `json:"k"`
	From string         `json:"f"`
	Refs []store.RowRef `json:"r"`
}

const msgRevoked = "revoked"

// maxRevocationRefs bounds the rows one message names, so it fits a gossip
// packet; the rest reach the replicas by hints and anti-entropy.
const maxRevocationRefs = 8

// announceRevocation broadcasts the rows of muts, a revocation written here.
func (r *Replicator) announceRevocation(muts []store.Mutation) {
	if r.cfg.Broadcast == nil {
		return
	}
	var refs []store.RowRef
	for _, m := range muts {
		if ref, ok := m.Ref(); ok {
			refs = append(refs, ref)
		}
	}
	for len(refs) > 0 {
		n := min(len(refs), maxRevocationRefs)
		b, err := json.Marshal(revocationMsg{Kind: msgRevoked, From: r.cfg.NodeID, Refs: refs[:n]})
		if err == nil {
			r.cfg.Broadcast(b)
		}
		refs = refs[n:]
	}
}

// HandleMessage takes a message another member broadcast (pass it as
// MembershipConfig.Message): a revocation is fetched from its writer and
// merged into the rows this member holds.
func (r *Replicator) HandleMessage(b []byte) {
	var msg revocationMsg
	if err := json.Unmarshal(b, &msg); err != nil || msg.Kind != msgRevoked || msg.From == r.cfg.NodeID || len(msg.Refs) == 0 {
		return
	}
	r.enqueue(func(ctx context.Context) {
		if err := r.takeRevocation(ctx, msg); err != nil {
			r.log.DebugContext(ctx, "revocation from the gossip not taken; anti-entropy will", "from", msg.From, "err", err)
		}
	}, nil)
}

func (r *Replicator) takeRevocation(ctx context.Context, msg revocationMsg) error {
	muts, err := r.fetch(ctx, msg.From, msg.Refs)
	if err != nil {
		return err
	}
	var mine []store.Mutation
	for _, m := range muts {
		p, err := m.Placement()
		if err != nil {
			continue
		}
		if p.Global || r.Holds(p.Key) {
			mine = append(mine, m)
		}
	}
	return r.mergeOn(ctx, r.cfg.NodeID, mine)
}
