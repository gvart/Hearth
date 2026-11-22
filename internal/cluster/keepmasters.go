// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// Keeping the masters (docs/cluster.md, "Keeping 3 masters").
//
// When fewer than --keep-masters masters are left, one master, the owner of
// the "keep-masters" loop on the master ring, promotes a live storage
// member to master, as `hearth cluster promote <member> master` does,
// decided and audited as cluster.promote by the hub. It promotes only a
// member whose latest join used a join token minted for it as a device at
// its enrollment (#328): the admin made that device hub-eligible, consenting
// to it becoming a master, and it was checked capable then. A member that
// joined with a token an admin created is never promoted this way.
//
// A master counts until it is removed: one down (dead, or left as a hub
// stopped cleanly does) still counts, so a restart promotes no one; the
// promotion follows its removal, by hand or after --member-dead-after. The
// hubs joining with a token granting master, and the minted join tokens not
// spent yet, count too, so the masters never pass MaxAutoMasters. As for a
// removal, the hub promotes only while it sees a strict majority of the
// members it knows alive, never during a hub CA rotation, one member at a
// time, and the next only once the gossip shows the last one master.

// DefaultKeepMasters is how many masters are kept (--keep-masters).
const DefaultKeepMasters = MaxAutoMasters

// errNoLongerNeeded stops a promotion that is no longer the one to make
// once it was approved: the masters, or the member, changed meanwhile.
var errNoLongerNeeded = errors.New("the promotion is no longer needed")

// keepPlan is what keeping the masters asks for: the member to promote, or
// Refused why none is (empty when there are masters enough).
type keepPlan struct {
	// Masters counts the masters, those down and to come included.
	Masters int
	Pick    string
	Refused string
}

// planKeepMasters decides, for self, which member to promote to keep keep
// masters, keep at most MaxAutoMasters. self sees members and the record
// down; coming is how many masters are on their way (joining, or with a
// minted join token not spent yet); eligible is, by node ID, when each
// hub-eligible member joined. The pick is the eligible live storage member
// that allows master and joined first, then the lowest node ID.
func planKeepMasters(self string, members []MemberInfo, down map[string]downMember, coming int,
	eligible map[string]time.Time, keep int,
) keepPlan {
	keep = min(keep, MaxAutoMasters)
	masters := map[string]bool{}
	for _, m := range members {
		if m.Roles.Has(RoleMaster) {
			masters[m.ID] = true
		}
	}
	for id, d := range down {
		if d.Roles.Has(RoleMaster) {
			masters[id] = true
		}
	}
	p := keepPlan{Masters: len(masters) + coming}
	if keep <= 0 || p.Masters >= keep {
		return p
	}
	live, known, ok := seesMajority(self, members, down)
	if !ok {
		p.Refused = notMajority(len(live), known)
		return p
	}
	var cands []MemberInfo
	for _, m := range members {
		if _, el := eligible[m.ID]; !el || m.State != MemberAlive || m.Roles.Has(RoleMaster) ||
			!m.Roles.Has(RoleStorage) || !m.AllowedRoles.Has(RoleMaster) || m.Draining || m.Syncing {
			continue
		}
		cands = append(cands, m)
	}
	if len(cands) == 0 {
		p.Refused = "no live storage member that joined as a hub-eligible device and allows master"
		return p
	}
	slices.SortFunc(cands, func(a, b MemberInfo) int {
		if c := eligible[a.ID].Compare(eligible[b.ID]); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	p.Pick = cands[0].ID
	return p
}

// KeepMasters is how many masters this hub keeps; zero if it never
// promotes a member to do so.
func (n *APNode) KeepMasters() int {
	if n.down == nil {
		return 0
	}
	return min(n.cfg.KeepMasters, MaxAutoMasters)
}

// keepPlanNow plans keeping the masters with what this hub sees now.
func (n *APNode) keepPlanNow(ctx context.Context) (keepPlan, error) {
	now := time.Now()
	eligible, err := n.st.JoinTokens().HubEligible(ctx)
	if err != nil {
		return keepPlan{}, err
	}
	joining, _, err := n.joining(ctx, "", now)
	if err != nil {
		return keepPlan{}, err
	}
	_, pending, err := n.st.JoinTokens().PendingMinted(ctx, now)
	if err != nil {
		return keepPlan{}, err
	}
	// A master another master removed may still be in this hub's record
	// until its next look: it no longer counts.
	down := n.down.snapshot()
	for id, d := range down {
		if d.Roles.Has(RoleMaster) && n.removed(id) {
			delete(down, id)
		}
	}
	p := planKeepMasters(n.cfg.NodeID, n.localMembers(), down, joining+pending, eligible, n.KeepMasters())
	if p.Pick != "" && n.cfg.AgentURL == "" {
		// The member promoted fetches the CA key at this hub's agent URL.
		p.Pick, p.Refused = "", "this hub does not know its own agent URL"
	}
	return p, nil
}

// RunKeepMasters promotes a hub-eligible storage member to master whenever
// fewer than KeepMasters masters are left, until ctx ends, each through pol
// as cluster.promote by this hub. It runs on the one master owning the
// loop. A promotion refused or failed is tried again after a while; a guard
// that holds the promotion back is logged once.
func (n *APNode) RunKeepMasters(ctx context.Context, pol *policy.Engine) error {
	if n.KeepMasters() <= 0 {
		return nil
	}
	every := n.deadEvery()
	t := time.NewTicker(every)
	defer t.Stop()
	k := masterKeeper{
		n: n, pol: pol, grace: time.Now().Add(2 * every), retryAfter: 60 * every, waitFor: 10 * every,
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			k.round(ctx, time.Now())
		}
	}
}

// masterKeeper is the state of the keep-masters loop.
type masterKeeper struct {
	n   *APNode
	pol *policy.Engine
	// grace: nothing is promoted before it, while the gossip finds the
	// members after a start.
	grace time.Time
	// retry is when a promotion refused or failed is tried again;
	// retryAfter how long that waits.
	retry      time.Time
	retryAfter time.Duration
	// promoted is the member last promoted, which the gossip is to show
	// master before the next promotion, until promotedBy (waitFor after).
	promoted   string
	promotedBy time.Time
	waitFor    time.Duration
	// logged is the guard last logged.
	logged string
}

func (k *masterKeeper) round(ctx context.Context, now time.Time) {
	n := k.n
	if now.Before(k.grace) || now.Before(k.retry) || !n.IsMaster() || n.rotationActive() {
		return
	}
	if k.promoted != "" {
		m := MemberInfo{}
		for _, x := range n.localMembers() {
			if x.ID == k.promoted {
				m = x
			}
		}
		if !m.Roles.Has(RoleMaster) && alive(m) && now.Before(k.promotedBy) {
			return
		}
		k.promoted = ""
	}
	p, err := n.keepPlanNow(ctx)
	if err != nil {
		n.log.WarnContext(ctx, "plan keeping the masters", "err", err)
		return
	}
	if p.Refused != "" {
		if k.logged != p.Refused {
			k.logged = p.Refused
			n.log.WarnContext(ctx, "fewer masters than --keep-masters, but none is promoted",
				"masters", p.Masters, "keep_masters", n.KeepMasters(), "reason", p.Refused)
		}
		return
	}
	k.logged = ""
	if p.Pick == "" {
		return
	}
	if err := n.promoteToKeep(ctx, k.pol, p); err != nil {
		k.retry = now.Add(k.retryAfter)
		n.log.WarnContext(ctx, "promote a member to keep the masters", "member", p.Pick, "err", err)
		return
	}
	k.promoted, k.promotedBy = p.Pick, now.Add(k.waitFor)
}

// promoteToKeep promotes the member p picked to master through pol, as
// cluster.promote by this hub, once it checked again that it is still the
// one to promote: a promotion held for approval may be approved after the
// masters changed. The member fetches the CA key from this hub over the
// pinned FetchCAKey channel, granted only while this promotion runs.
func (n *APNode) promoteToKeep(ctx context.Context, pol *policy.Engine, p keepPlan) error {
	reason := fmt.Sprintf("keep %d masters", n.KeepMasters())
	req := policy.Request{
		ActorKind: policy.ActorHub, ActorID: n.cfg.NodeID, Action: policy.ClusterPromote, Target: p.Pick,
		Detail: map[string]any{"role": string(RoleMaster), "reason": reason, "masters": p.Masters},
	}
	return pol.Do(ctx, req, func(ctx context.Context) error {
		if n.rotationActive() {
			return ErrRotationRoles
		}
		still, err := n.keepPlanNow(ctx)
		if err != nil {
			return err
		}
		if still.Pick != p.Pick {
			return errNoLongerNeeded
		}
		if _, err := n.Promote(ctx, p.Pick, RoleMaster); err != nil {
			return err
		}
		n.log.InfoContext(ctx, "promoted a member to master automatically", "member", p.Pick, "reason", reason,
			"masters", p.Masters)
		return nil
	})
}
