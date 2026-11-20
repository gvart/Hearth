// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// Promote, demote and remove (docs/design/ap-cluster.md §2, §3, §6).
//
// An admin asks a master (API, UI, or the CLI on its host, each through
// policy as cluster.promote, cluster.demote or cluster.remove). The master
// checks what it can from the gossip (the member exists and is alive, the
// role is in its allowed roles, the last master or storage member stays)
// and sends the change to the member over the masters' link; the member
// checks its own --allow-roles, the ceiling, again and changes its roles,
// which it records in its data dir and says on the gossip.
//
//   - storage+: the member drops the shard rows it kept from before, joins
//     the ring and copies its buckets from the others; it is "syncing", and
//     serves no reads, until it has them all.
//   - master+: the member fetches the CA key from the master that asked,
//     over the pinned mutual-TLS ClusterService (cluster.ca.fetch_key,
//     audited, honoured only during that promotion), and starts serving.
//   - storage-: the member hands its rows off and keeps the role until each
//     has N copies on the others ("draining"); then it leaves the ring.
//   - master-: the member spends its unused tokens and join tokens, expires
//     its pending approvals, deletes the CA key and stops serving: its
//     agents move to another master, its share of the master ring to others.
//   - remove: a member gone for good is revoked (deny-wins, announced on the
//     gossip) and forgotten, so the others re-replicate its rows.

// Role change errors. RoleErrorKind names each for the API.
var (
	ErrUnknownMember = errors.New("no such cluster member")
	// ErrAgentHost refuses a role for an enrolled device: the agent cannot
	// hold storage or master.
	ErrAgentHost = errors.New("this is an agent host: an agent cannot take the storage or master role; " +
		"run `hearth hub --cluster-mode ap --join <master URL> --allow-roles storage,master` on it to make it a cluster member")
	// ErrRoleCeiling refuses a role the member's own --allow-roles does not
	// list.
	ErrRoleCeiling = errors.New("the role is not in the member's --allow-roles")
	ErrLastMaster  = errors.New("the last master cannot be demoted or removed")
	// ErrKeepsNoRole refuses to leave a member with neither storage nor
	// master: it would leave the cluster.
	ErrKeepsNoRole   = errors.New("a member keeps storage or master: to take a hub out, stop it and run `hearth cluster remove`")
	ErrNoChange      = errors.New("the member already is so")
	ErrMemberDown    = errors.New("the member is not alive")
	ErrRemoveSelf    = errors.New("a hub cannot remove itself: run the removal on another master")
	ErrNotMasterHere = errors.New("this hub is not a master: ask a master")
	ErrBadRole       = errors.New("the role is storage or master")
)

var roleKinds = map[string]error{
	"unknown_member": ErrUnknownMember,
	"agent_host":     ErrAgentHost,
	"not_allowed":    ErrRoleCeiling,
	"last_master":    ErrLastMaster,
	"last_storage":   ErrLastStorage,
	"keeps_no_role":  ErrKeepsNoRole,
	"no_change":      ErrNoChange,
	"member_down":    ErrMemberDown,
	"remove_self":    ErrRemoveSelf,
	"not_master":     ErrNotMasterHere,
	"bad_role":       ErrBadRole,
}

// RoleErrorKind is the kind of a role change error ("last_master", ...), or
// "" for any other error.
func RoleErrorKind(err error) string {
	for k, target := range roleKinds {
		if errors.Is(err, target) {
			return k
		}
	}
	return ""
}

// Role change states.
const (
	RoleDone     = "done"
	RoleSyncing  = "syncing"
	RoleDraining = "draining"
)

// RoleChange is what a promotion or demotion did.
type RoleChange struct {
	Member string `json:"member"`
	Role   Role   `json:"role"`
	// State is done, syncing (promoted to storage, copying its rows) or
	// draining (being demoted from storage, handing its rows off).
	State string `json:"state"`
}

// Removal is what removing a member did.
type Removal struct {
	Member string `json:"member"`
	// Revoked counts the hub certificates revoked.
	Revoked int `json:"revoked"`
}

// roleRequest is a role change a master sends a member.
type roleRequest struct {
	Promote bool `json:"promote"`
	Role    Role `json:"role"`
	// FromURL is the asking master's agent-facing URL: a member promoted to
	// master fetches the CA key there.
	FromURL string `json:"from_url,omitempty"`
}

type roleReply struct {
	State string     `json:"state,omitempty"`
	Error *wireError `json:"error,omitempty"`
}

const (
	rolesPath = "/cluster/v1/roles"
	// keyGrantTTL bounds how long a promotion's CA key grant lasts.
	keyGrantTTL = time.Minute
	// demotedBy decides the approvals a demoted master leaves open.
	demotedBy = "expired: master demoted"
)

func checkRole(role Role) error {
	if role != RoleStorage && role != RoleMaster {
		return fmt.Errorf("%w, not %q", ErrBadRole, role)
	}
	return nil
}

// member returns the member id as the gossip sees it.
func (n *APNode) member(ctx context.Context, id string) (MemberInfo, error) {
	for _, m := range n.membership.Members() {
		if m.ID == id {
			return m, nil
		}
	}
	if n.st != nil {
		if _, err := n.st.Devices().Get(ctx, id); err == nil {
			return MemberInfo{}, fmt.Errorf("%s: %w", id, ErrAgentHost)
		}
	}
	return MemberInfo{}, fmt.Errorf("%s: %w", id, ErrUnknownMember)
}

func alive(m MemberInfo) bool { return m.State == MemberAlive || m.State == MemberSuspect }

// count counts the members other than but with role that would remain. A
// storage member counts alive or not, as its rows are still there (a drain
// waits for it); one being drained does not. A master counts only alive: a
// dead one cannot serve, promote or hand out the CA key, so it is no
// reason to let the last live master go.
func (n *APNode) count(role Role, but string) int {
	c := 0
	for _, m := range n.membership.Members() {
		if m.ID == but || m.State == MemberLeft || !m.Roles.Has(role) {
			continue
		}
		if role == RoleStorage && m.Draining || role == RoleMaster && !alive(m) {
			continue
		}
		c++
	}
	return c
}

// Promote gives member id role: the member must allow it (--allow-roles).
// This hub must be a master.
func (n *APNode) Promote(ctx context.Context, id string, role Role) (RoleChange, error) {
	return n.changeRole(ctx, id, role, true)
}

// Demote takes role from member id. The last master is never demoted, nor
// the last storage member, nor a member's last role.
func (n *APNode) Demote(ctx context.Context, id string, role Role) (RoleChange, error) {
	return n.changeRole(ctx, id, role, false)
}

func (n *APNode) changeRole(ctx context.Context, id string, role Role, promote bool) (RoleChange, error) {
	if err := checkRole(role); err != nil {
		return RoleChange{}, err
	}
	if !n.IsMaster() {
		return RoleChange{}, ErrNotMasterHere
	}
	m, err := n.member(ctx, id)
	if err != nil {
		return RoleChange{}, err
	}
	if !alive(m) {
		return RoleChange{}, fmt.Errorf("%s is %s: %w", id, m.State, ErrMemberDown)
	}
	switch {
	case promote && !m.AllowedRoles.Has(role):
		return RoleChange{}, fmt.Errorf("%s allows %s: %w", id, m.AllowedRoles, ErrRoleCeiling)
	case !promote && !m.Roles.Has(role):
		return RoleChange{}, fmt.Errorf("%s is not %s: %w", id, role, ErrNoChange)
	case !promote && !(m.Roles &^ role.bit()).Gossips():
		return RoleChange{}, ErrKeepsNoRole
	case !promote && role == RoleMaster && n.count(RoleMaster, id) == 0:
		return RoleChange{}, ErrLastMaster
	case !promote && role == RoleStorage && !m.Draining && n.count(RoleStorage, id) == 0:
		return RoleChange{}, ErrLastStorage
	}
	req := roleRequest{Promote: promote, Role: role, FromURL: n.cfg.AgentURL}
	if promote && role == RoleMaster && id != n.cfg.NodeID {
		n.grantKey(id)
		defer n.revokeGrant(id)
	}
	state, err := n.sendRoleChange(ctx, id, req)
	if err != nil {
		return RoleChange{}, err
	}
	return RoleChange{Member: id, Role: role, State: state}, nil
}

// sendRoleChange has member id apply req: at once if it is this hub.
func (n *APNode) sendRoleChange(ctx context.Context, id string, req roleRequest) (string, error) {
	if id == n.cfg.NodeID {
		return n.applyRoleChange(ctx, req)
	}
	b, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+id+rolesPath, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := n.link.Client().Do(hreq)
	if err != nil {
		return "", fmt.Errorf("reach %s: %w", id, err)
	}
	defer resp.Body.Close()
	var reply roleReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&reply); err != nil {
		return "", fmt.Errorf("%s answered %s", id, resp.Status)
	}
	if reply.Error != nil {
		if target, ok := roleKinds[reply.Error.Kind]; ok {
			return "", &kindError{msg: reply.Error.Message, target: target}
		}
		return "", reply.Error.toError()
	}
	return reply.State, nil
}

// serveRoles applies a role change a live master sent (MasterLink checked
// it is one).
func (n *APNode) serveRoles(w http.ResponseWriter, r *http.Request) {
	var req roleRequest
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n.log.InfoContext(r.Context(), "role change asked by a master", "master", MasterPeer(r.Context()),
		"role", req.Role, "promote", req.Promote)
	state, err := n.applyRoleChange(r.Context(), req)
	reply := roleReply{State: state}
	if err != nil {
		reply.Error = &wireError{Kind: RoleErrorKind(err), Message: err.Error()}
		if reply.Error.Kind == "" {
			reply.Error = toWireError(err)
		}
	}
	writeJSON(w, reply)
}

// applyRoleChange changes this member's roles as req asks, within its own
// --allow-roles.
func (n *APNode) applyRoleChange(ctx context.Context, req roleRequest) (string, error) {
	if err := checkRole(req.Role); err != nil {
		return "", err
	}
	n.rolesMu.Lock()
	defer n.rolesMu.Unlock()
	lr := n.local
	has := lr.Roles.Has(req.Role)
	switch {
	case req.Promote && !n.cfg.Allowed.Has(req.Role):
		return "", fmt.Errorf("%s allows %s: %w", n.cfg.NodeID, n.cfg.Allowed, ErrRoleCeiling)
	case req.Promote && req.Role == RoleStorage && has && lr.Draining:
		// Promoting a member being drained calls the demotion off.
		lr.Draining = false
		if err := n.setLocal(lr); err != nil {
			return "", err
		}
		n.log.InfoContext(ctx, "demotion from storage called off: keeping the role")
		return RoleDone, nil
	case req.Promote && has, !req.Promote && !has:
		return "", ErrNoChange
	case !req.Promote && !(lr.Roles &^ req.Role.bit()).Gossips():
		return "", ErrKeepsNoRole
	case !req.Promote && req.Role == RoleMaster && n.membership != nil && n.count(RoleMaster, n.cfg.NodeID) == 0:
		// Checked again here: two masters demoting each other at once
		// must not both go.
		return "", ErrLastMaster
	}
	switch {
	case req.Promote && req.Role == RoleStorage:
		// Rows kept from before a demotion are stale: copied back, one whose
		// tombstone is gone elsewhere would come back to life.
		dropped, err := n.st.DropShardRows(ctx)
		if err != nil {
			return "", err
		}
		lr.Roles |= RoleStorage.bit()
		lr.Syncing = true
		if err := n.setLocal(lr); err != nil {
			return "", err
		}
		n.log.InfoContext(ctx, "promoted to storage: copying this member's buckets", "stale_rows_dropped", dropped)
		n.kickRoles()
		return RoleSyncing, nil
	case req.Promote:
		if !n.cfg.CA.HasKey() {
			key, err := n.fetchCAKey(ctx, req.FromURL)
			if err != nil {
				return "", fmt.Errorf("fetch the CA key: %w", err)
			}
			if err := n.cfg.CA.SetKey(key); err != nil {
				return "", err
			}
		}
		lr.Roles |= RoleMaster.bit()
		if err := n.setLocal(lr); err != nil {
			return "", err
		}
		n.log.InfoContext(ctx, "promoted to master")
		return RoleDone, nil
	case req.Role == RoleStorage:
		if lr.Draining {
			return RoleDraining, nil
		}
		lr.Draining = true
		if err := n.setLocal(lr); err != nil {
			return "", err
		}
		n.log.InfoContext(ctx, "demotion from storage: handing this member's rows off")
		n.kickRoles()
		return RoleDraining, nil
	default:
		closed, err := n.st.CloseOwned(ctx, n.cfg.NodeID, demotedBy, time.Now())
		if err != nil {
			return "", fmt.Errorf("close this master's tokens and approvals: %w", err)
		}
		lr.Roles &^= RoleMaster.bit()
		if err := n.setLocal(lr); err != nil {
			return "", err
		}
		if err := n.cfg.CA.DropKey(); err != nil {
			n.log.ErrorContext(ctx, "delete the CA key of a demoted master", "err", err)
		}
		n.log.InfoContext(ctx, "demoted from master: CA key deleted, agents move to the other masters",
			"tokens_spent", closed.Tokens, "join_tokens_spent", closed.JoinTokens, "approvals_expired", closed.Approvals)
		return RoleDone, nil
	}
}

// setLocal records lr, says it on the gossip and applies it here. The
// caller holds rolesMu.
func (n *APNode) setLocal(lr LocalRoles) error {
	if err := saveLocalRoles(n.cfg.DataDir, lr); err != nil {
		return err
	}
	wasMaster := n.local.Roles.Has(RoleMaster)
	n.local = lr
	n.setRoles(lr.Roles)
	n.rep.SetLocal(lr.Roles.Has(RoleStorage), lr.Syncing)
	if n.membership != nil {
		if err := n.membership.SetLocal(LocalState{Roles: lr.Roles, Syncing: lr.Syncing, Draining: lr.Draining}); err != nil {
			return err
		}
	}
	if n.masters != nil {
		n.masters.Refresh()
	}
	if wasMaster != lr.Roles.Has(RoleMaster) {
		n.notifyRoles()
	}
	return nil
}

// RemoveMember removes member id from the cluster for good: its hub
// certificates are revoked (deny-wins, announced on the gossip), every
// member forgets it, and the others re-replicate the rows it held. A hub
// does not remove itself, nor the last master or storage member.
func (n *APNode) RemoveMember(ctx context.Context, id string) (Removal, error) {
	if err := ValidNodeID(id); err != nil {
		return Removal{}, err
	}
	if !n.IsMaster() {
		return Removal{}, ErrNotMasterHere
	}
	if id == n.cfg.NodeID {
		return Removal{}, ErrRemoveSelf
	}
	m, err := n.member(ctx, id)
	if err != nil {
		certs, cerr := n.st.Hubs().Certs(ctx, id)
		if cerr != nil || len(certs) == 0 || errors.Is(err, ErrAgentHost) {
			return Removal{}, err
		}
		// Not in the gossip any more (this hub restarted since), but a hub
		// of the cluster: its certificates are still revoked.
	}
	if m.Roles.Has(RoleStorage) && n.count(RoleStorage, id) == 0 {
		return Removal{}, ErrLastStorage
	}
	if m.Roles.Has(RoleMaster) && n.count(RoleMaster, id) == 0 {
		return Removal{}, ErrLastMaster
	}
	revoked, err := n.st.Hubs().RevokeCerts(ctx, id, time.Now())
	if err != nil {
		return Removal{}, err
	}
	n.membership.Forget(id)
	n.membership.closeRevoked(func(c *x509.Certificate) bool {
		got, err := pki.HubNodeID(c)
		return err == nil && got == id
	})
	n.membership.Broadcast(mustJSON(removedMsg{Kind: msgRemoved, ID: id}))
	n.log.InfoContext(ctx, "removed a member from the cluster", "member", id, "certs_revoked", revoked)
	return Removal{Member: id, Revoked: revoked}, nil
}

// removedMsg tells the members that ID was removed.
type removedMsg struct {
	Kind string `json:"k"`
	ID   string `json:"id"`
}

const msgRemoved = "removed"

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// handleMessage dispatches a message another member broadcast.
func (n *APNode) handleMessage(b []byte) {
	var msg removedMsg
	if json.Unmarshal(b, &msg) == nil && msg.Kind == msgRemoved {
		if msg.ID != n.cfg.NodeID && ValidNodeID(msg.ID) == nil {
			n.membership.Forget(msg.ID)
		}
		return
	}
	n.rep.HandleMessage(b)
}

// removed reports whether member id was removed: it has hub certificates,
// all revoked.
func (n *APNode) removed(id string) bool {
	if n.st == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	certs, err := n.st.Hubs().Certs(ctx, id)
	if err != nil || len(certs) == 0 {
		return false
	}
	return !slices.ContainsFunc(certs, func(c store.HubCert) bool { return !c.Revoked })
}
