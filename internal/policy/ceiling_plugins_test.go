// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestPluginWithinCeiling(t *testing.T) {
	c := &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{
		{Name: "lamp", MaxClass: "safe"},
		{Name: "load", MaxClass: "read"},
	}}
	tests := []struct {
		name, plugin string
		class        Class
		ok           bool
	}{
		{"install a listed plugin", "lamp", "", true},
		{"read under safe", "lamp", Read, true},
		{"safe at safe", "lamp", Safe, true},
		{"dangerous above safe", "lamp", Dangerous, false},
		{"safe above read", "load", Safe, false},
		{"not listed", "other", Read, false},
		{"not listed, install", "other", "", false},
		{"unknown class", "lamp", Class("root"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PluginWithinCeiling(c, tt.plugin, tt.class)
			if tt.ok != (err == nil) {
				t.Fatalf("PluginWithinCeiling(%s, %q) = %v, want ok %v", tt.plugin, tt.class, err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrBeyondCeiling) {
				t.Fatalf("error %v does not wrap ErrBeyondCeiling", err)
			}
		})
	}
	if err := PluginWithinCeiling(nil, "lamp", ""); !errors.Is(err, ErrBeyondCeiling) {
		t.Fatalf("a nil ceiling allowed a plugin: %v", err)
	}
}

func TestCheckPluginGrants(t *testing.T) {
	tests := []struct {
		name   string
		grants []*agentv1.PluginGrant
		ok     bool
	}{
		{"none", nil, true},
		{"valid", []*agentv1.PluginGrant{{Name: "go-lamp", MaxClass: "dangerous"}, {Name: "a.b_c", MaxClass: "read"}}, true},
		{"path in name", []*agentv1.PluginGrant{{Name: "../x", MaxClass: "read"}}, false},
		{"slash in name", []*agentv1.PluginGrant{{Name: "a/b", MaxClass: "read"}}, false},
		{"empty name", []*agentv1.PluginGrant{{Name: "", MaxClass: "read"}}, false},
		{"bad class", []*agentv1.PluginGrant{{Name: "lamp", MaxClass: "admin"}}, false},
		{"no class", []*agentv1.PluginGrant{{Name: "lamp"}}, false},
		{"twice", []*agentv1.PluginGrant{{Name: "lamp", MaxClass: "read"}, {Name: "lamp", MaxClass: "safe"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckHubCeiling(&agentv1.Ceiling{Plugins: tt.grants})
			if tt.ok != (err == nil) {
				t.Fatalf("CheckHubCeiling = %v, want ok %v", err, tt.ok)
			}
		})
	}
}
