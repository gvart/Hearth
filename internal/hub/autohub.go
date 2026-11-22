// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// hubCounter counts an AP cluster's members for the caps on the hubs
// devices become on their own (#328). *cluster.APNode is one.
type hubCounter interface {
	// HubCounts counts the hubs with the master and the storage role, but
	// for except: the members that have not left and the hubs that joined
	// and are not in the gossip yet.
	HubCounts(ctx context.Context, except string) (masters, storage int, err error)
}

// autoHubJoinTTL is how long a join token minted at an enrollment lasts:
// the installer starts the hub right after the agent enrolls.
const autoHubJoinTTL = 15 * time.Minute

// Whether an enrolling device may become a hub, as the device.enroll entry
// records it: why not, or, for a capable device (hubOffered), whether its
// join token was minted (hub_roles) or refused (hub_refused says why).
const (
	hubNotEligible = "not eligible"
	hubNotOffered  = "not offered"
	hubNotCapable  = "not capable"
	hubOffered     = "offered"
	hubMinted      = "minted"
	hubRefused     = "refused"
)

// hubOutcome is whether a device enrolling with a token of hubRoles and offer
// may become a hub: hubOffered, or why not, with the reason a device that
// is not capable is told.
func hubOutcome(hubRoles string, offer *agentv1.HubOffer) (outcome, why string) {
	switch {
	case hubRoles == "":
		return hubNotEligible, "the enrollment token does not let this device become a hub"
	case offer == nil:
		return hubNotOffered, ""
	}
	if err := cluster.HubCapable(cluster.HubOffer{
		OS: offer.GetOs(), Arch: offer.GetArch(), MemTotal: offer.GetMemTotal(), DiskFree: offer.GetDiskFree(),
	}); err != nil {
		return hubNotCapable, "this device cannot be a hub: " + err.Error()
	}
	return hubOffered, ""
}

// mintHubJoin mints, for the device deviceID that just enrolled with the
// enrollment token whose handle is handle, a cluster join token of at most
// hubRoles: storage while fewer than cluster.MaxAutoStorage storage members
// are counted, and master too while fewer than cluster.MaxAutoMasters
// masters are. Members that have not left count, and so do the join tokens
// minted before and not yet spent. The mint is its own cluster.token.create
// decision, by the enrollment token; the token is never logged nor
// audited. A refusal says why the device stays an agent.
func (e *Enroller) mintHubJoin(ctx context.Context, deviceID, handle, hubRoles string) *agentv1.HubJoin {
	refuse := func(why string) *agentv1.HubJoin { return &agentv1.HubJoin{Refused: why} }
	if e.hubs == nil || e.masters == nil {
		return refuse("this hub is not a member of an AP cluster")
	}
	allowed, err := cluster.ParseRoles(hubRoles)
	if err != nil {
		return refuse("the enrollment token's hub roles are not valid")
	}
	url := e.masters.AgentURLOf(ctx, e.masters.Self())
	if url == "" {
		return refuse("this hub does not know its own agent URL")
	}
	// One count and mint at a time: two enrollments in a row on this
	// master cannot both take the last place.
	e.mintMu.Lock()
	defer e.mintMu.Unlock()
	now := e.now()
	roles, why := hubJoinRoles(ctx, e.hubs, e.store, now, allowed, e.log)
	if why != "" {
		return refuse(why)
	}
	tok, err := pki.NewToken(e.ca.Cert())
	if err != nil {
		return refuse("this hub could not create a join token")
	}
	err = e.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorToken, ActorID: handle, Action: policy.ClusterTokenCreate, Target: deviceID,
		Detail: map[string]any{"roles": roles.String(), "device_id": deviceID, "ttl": autoHubJoinTTL.String()},
	}, func(ctx context.Context) error {
		return e.store.JoinTokens().CreateFor(ctx, tok.Secret, now.Add(autoHubJoinTTL), roles.String(), deviceID)
	})
	switch {
	case err == nil:
	case errors.Is(err, policy.ErrDenied) && strings.Contains(err.Error(), policy.ErrIsolated):
		return refuse("this hub is cut off from its cluster")
	case errors.Is(err, policy.ErrDenied):
		return refuse("the join token was denied by policy")
	default:
		e.log.ErrorContext(ctx, "mint a hub join token", "device_id", deviceID, "err", err)
		return refuse("this hub could not mint a join token")
	}
	e.log.InfoContext(ctx, "device may become a hub", "device_id", deviceID, "roles", roles.String())
	return &agentv1.HubJoin{Url: url, Token: tok.EncodeJoin(), Roles: roles.Strings()}
}

// hubJoinRoles is the roles of a join token minted now for a device, of at
// most allowed: storage while fewer than cluster.MaxAutoStorage storage
// members are counted, and master too while fewer than
// cluster.MaxAutoMasters masters are, counting the members that have not
// left and the minted join tokens not yet spent. Past the storage cap it
// says why the device gets none. The caller serializes counting and minting.
func hubJoinRoles(ctx context.Context, hubs hubCounter, st *store.Store, now time.Time, allowed cluster.RoleSet,
	log *slog.Logger,
) (cluster.RoleSet, string) {
	masters, storage, err := hubs.HubCounts(ctx, "")
	if err != nil {
		log.ErrorContext(ctx, "count the hubs", "err", err)
		return 0, "this hub could not count the cluster's hubs"
	}
	pending, pendingMasters, err := st.JoinTokens().PendingMinted(ctx, now)
	if err != nil {
		log.ErrorContext(ctx, "count the hubs to come", "err", err)
		return 0, "this hub could not count the cluster's hubs"
	}
	if storage+pending >= cluster.MaxAutoStorage {
		return 0, fmt.Sprintf("the cluster has %d storage members already, the most devices become on their own",
			cluster.MaxAutoStorage)
	}
	roles := cluster.RolesOf(cluster.RoleStorage)
	if masters+pendingMasters < cluster.MaxAutoMasters && allowed.Has(cluster.RoleMaster) {
		roles = cluster.RolesOf(cluster.RoleStorage, cluster.RoleMaster)
	}
	return roles, ""
}
