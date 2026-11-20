// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRoles(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    RoleSet
		wantErr string
	}{
		{in: "", want: 0},
		{in: "node", want: AgentRoles},
		{in: "storage,master", want: HubRoles},
		{in: " Master , storage ,", want: HubRoles},
		{in: "master,master", want: RolesOf(RoleMaster)},
		{in: "node,storage,master", want: RolesOf(RoleNode, RoleStorage, RoleMaster)},
		{in: "voter", wantErr: `unknown role "voter"`},
		{in: "storage,leader", wantErr: `unknown role "leader"`},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseRoles(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ParseRoles(%q) = %v, %v; want error %q", tc.in, got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ParseRoles(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestCheckCeiling(t *testing.T) {
	for _, tc := range []struct {
		name           string
		roles, allowed RoleSet
		wantErr        string
	}{
		{name: "hub default", roles: HubRoles, allowed: HubRoles},
		{name: "agent default", roles: AgentRoles, allowed: AgentRoles},
		{name: "subset", roles: RolesOf(RoleStorage), allowed: RolesOf(RoleNode, RoleStorage, RoleMaster)},
		{name: "nothing", roles: 0, allowed: 0},
		{name: "master not allowed", roles: HubRoles, allowed: RolesOf(RoleStorage), wantErr: "role master not allowed"},
		{name: "none allowed", roles: HubRoles, allowed: 0, wantErr: "role storage,master not allowed on this host (--allow-roles none)"},
		{name: "storage on a TV", roles: RolesOf(RoleNode, RoleStorage), allowed: AgentRoles, wantErr: "role storage not allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckCeiling(tc.roles, tc.allowed)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckCeiling(%v, %v) = %v", tc.roles, tc.allowed, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CheckCeiling(%v, %v) = %v; want %q", tc.roles, tc.allowed, err, tc.wantErr)
			}
		})
	}
}

func TestRoleSetStringAndGossips(t *testing.T) {
	for _, tc := range []struct {
		s       RoleSet
		str     string
		gossips bool
	}{
		{0, "none", false},
		{AgentRoles, "node", false},
		{HubRoles, "storage,master", true},
		{RolesOf(RoleStorage), "storage", true},
		{RolesOf(RoleMaster, RoleNode), "node,master", true},
	} {
		if got := tc.s.String(); got != tc.str {
			t.Errorf("String() = %q, want %q", got, tc.str)
		}
		if got := tc.s.Gossips(); got != tc.gossips {
			t.Errorf("%v.Gossips() = %v, want %v", tc.s, got, tc.gossips)
		}
	}
}

func TestRoleSetJSON(t *testing.T) {
	b, err := json.Marshal(HubRoles)
	if err != nil || string(b) != `["storage","master"]` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
	var s RoleSet
	if err := json.Unmarshal(b, &s); err != nil || s != HubRoles {
		t.Fatalf("Unmarshal = %v, %v", s, err)
	}
	if err := json.Unmarshal([]byte(`["master","root"]`), &s); err == nil {
		t.Fatal("Unmarshal accepted an unknown role")
	}
	if b, _ := json.Marshal(RoleSet(0)); string(b) != `[]` {
		t.Fatalf("empty set = %s, want []", b)
	}
}
