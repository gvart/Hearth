// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"slices"
	"time"
)

// Roles are this member's roles now.
func (n *APNode) Roles() RoleSet {
	n.rolesMu.Lock()
	defer n.rolesMu.Unlock()
	return n.local.Roles
}

// LocalRoles are this member's roles and the role change under way.
func (n *APNode) LocalRoles() LocalRoles {
	n.rolesMu.Lock()
	defer n.rolesMu.Unlock()
	return n.local
}

// IsMaster reports whether this member is a master now: one serves the API,
// agents and enrollments, and holds the CA key.
func (n *APNode) IsMaster() bool { return RoleSet(n.roles.Load()).Has(RoleMaster) }

// RoleChanges returns a channel signalled (without blocking) whenever this
// member gains or loses the master role, and a function that stops it.
func (n *APNode) RoleChanges() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	n.subsMu.Lock()
	n.roleSubs = append(n.roleSubs, ch)
	n.subsMu.Unlock()
	return ch, func() {
		n.subsMu.Lock()
		defer n.subsMu.Unlock()
		n.roleSubs = slices.DeleteFunc(n.roleSubs, func(c chan struct{}) bool { return c == ch })
	}
}

func (n *APNode) notifyRoles() {
	n.subsMu.Lock()
	defer n.subsMu.Unlock()
	for _, ch := range n.roleSubs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// kickRoles runs a drain or catch-up round now.
func (n *APNode) kickRoles() {
	select {
	case n.rolesKick <- struct{}{}:
	default:
	}
}

// onSynced records that this member, promoted to storage, caught up.
func (n *APNode) onSynced() {
	n.rolesMu.Lock()
	defer n.rolesMu.Unlock()
	if !n.local.Syncing {
		return
	}
	lr := n.local
	lr.Syncing = false
	if err := n.setLocal(lr); err != nil {
		n.log.Error("record the end of the catch-up after the promotion", "err", err)
	}
}

// runRoles drives the role change under way until ctx ends: the drain
// before a demotion from storage, the catch-up after a promotion to it.
func (n *APNode) runRoles(ctx context.Context) {
	t := time.NewTicker(n.cfg.RolesEvery)
	defer t.Stop()
	for {
		lr := n.LocalRoles()
		if lr.Draining {
			n.drainRound(ctx)
		}
		if lr.Syncing {
			n.rep.CatchUp(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-n.rolesKick:
		}
	}
}

// drainRound runs one round of the drain and, once every row this member
// holds has its copies, takes the storage role away.
func (n *APNode) drainRound(ctx context.Context) {
	p, err := n.rep.Drain(ctx)
	if err != nil {
		if errors.Is(err, ErrLastStorage) {
			n.log.WarnContext(ctx, "demotion from storage on hold: no other storage member to hand the rows to")
		} else if ctx.Err() == nil {
			n.log.WarnContext(ctx, "demotion from storage: hand-off round failed", "err", err)
		}
		return
	}
	n.rolesMu.Lock()
	defer n.rolesMu.Unlock()
	if !n.local.Draining {
		return // called off meanwhile
	}
	if !p.Complete() {
		n.log.InfoContext(ctx, "demotion from storage: handing rows off", "buckets_done", p.Done,
			"buckets", p.Total, "waiting_for", p.Waiting)
		ls := LocalState{Roles: n.local.Roles, Draining: true, Progress: p.Percent()}
		if err := n.membership.SetLocal(ls); err != nil {
			n.log.WarnContext(ctx, "announce the drain's progress", "err", err)
		}
		return
	}
	lr := n.local
	lr.Roles &^= RoleStorage.bit()
	lr.Draining = false
	if err := n.setLocal(lr); err != nil {
		n.log.ErrorContext(ctx, "demotion from storage: record the roles", "err", err)
		return
	}
	n.log.InfoContext(ctx, "demoted from storage: every row this member held has its copies on the others",
		"buckets", p.Total)
}
