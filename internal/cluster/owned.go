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

// usesSchema keeps the owner's uses in the hints database.
const usesSchema = `CREATE TABLE IF NOT EXISTS owned_uses (
	key TEXT PRIMARY KEY
) STRICT`

// ownedUses is the owner's own record of the master-owned rows it used.
type ownedUses struct {
	mu  sync.Mutex
	db  *sql.DB // nil keeps them in memory only
	mem map[string]bool
}

func newOwnedUses(ctx context.Context, h *Hints) (*ownedUses, error) {
	u := &ownedUses{mem: map[string]bool{}}
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
	res, err := r.applyRouted(ctx, cmd)
	if err == nil || mayHaveApplied(err) {
		if merr := u.mark(context.WithoutCancel(ctx), key); merr != nil {
			r.log.ErrorContext(ctx, "record a use of a master-owned row", "op", cmd.Op(), "err", merr)
		}
	}
	return res, err
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
