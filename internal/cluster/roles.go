// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Role is one of a host's cluster roles (docs/design/ap-cluster.md §2).
type Role string

// The roles. Any combination is valid.
const (
	// RoleNode runs the agent: facts, heartbeat, exec.
	RoleNode Role = "node"
	// RoleStorage holds a shard replica of the store.
	RoleStorage Role = "storage"
	// RoleMaster serves the API, UI, MCP and agent streams, and runs
	// automations, runbooks, enrollment and the CA.
	RoleMaster Role = "master"
)

// allRoles lists the roles in display order.
var allRoles = []Role{RoleNode, RoleStorage, RoleMaster}

func (r Role) bit() RoleSet {
	for i, x := range allRoles {
		if x == r {
			return 1 << i
		}
	}
	return 0
}

// RoleSet is a set of roles.
type RoleSet uint8

// Default role sets: `hearth hub` is {master, storage}, `hearth agent` {node}.
var (
	HubRoles   = RoleMaster.bit() | RoleStorage.bit()
	AgentRoles = RoleNode.bit()
)

// RolesOf returns the set of rs.
func RolesOf(rs ...Role) RoleSet {
	var s RoleSet
	for _, r := range rs {
		s |= r.bit()
	}
	return s
}

// ParseRoles parses a comma-separated role list, such as "storage,master".
// Blanks are ignored; an empty list is the empty set. An unknown role is an
// error.
func ParseRoles(s string) (RoleSet, error) {
	var set RoleSet
	for _, f := range strings.Split(s, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		b := Role(f).bit()
		if b == 0 {
			return 0, fmt.Errorf("unknown role %q: want node, storage or master", f)
		}
		set |= b
	}
	return set, nil
}

// Has reports whether s holds r.
func (s RoleSet) Has(r Role) bool {
	b := r.bit()
	return b != 0 && s&b == b
}

// Roles lists the roles of s in display order.
func (s RoleSet) Roles() []Role {
	out := []Role{}
	for _, r := range allRoles {
		if s.Has(r) {
			out = append(out, r)
		}
	}
	return out
}

// String is s as a comma-separated list, or "none".
func (s RoleSet) String() string {
	rs := s.Roles()
	if len(rs) == 0 {
		return "none"
	}
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = string(r)
	}
	return strings.Join(parts, ",")
}

// Gossips reports whether a host with s takes part in membership: storage
// and master members do, node-only hosts do not.
func (s RoleSet) Gossips() bool { return s.Has(RoleStorage) || s.Has(RoleMaster) }

// CheckCeiling refuses roles that allowed, the host's --allow-roles, does not
// list: the host's local config is the capability ceiling.
func CheckCeiling(roles, allowed RoleSet) error {
	if extra := roles &^ allowed; extra != 0 {
		return fmt.Errorf("role %s not allowed on this host (--allow-roles %s)", extra, allowed)
	}
	return nil
}

// MarshalJSON encodes s as a list of role names.
func (s RoleSet) MarshalJSON() ([]byte, error) { return json.Marshal(s.Roles()) }

// UnmarshalJSON decodes a list of role names; an unknown one is an error.
func (s *RoleSet) UnmarshalJSON(b []byte) error {
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return err
	}
	set, err := ParseRoles(strings.Join(names, ","))
	if err != nil {
		return err
	}
	*s = set
	return nil
}
