// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"strings"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

var (
	digestA = strings.Repeat("a", 64)
	digestB = strings.Repeat("b", 64)
)

func TestPluginWithinCeiling(t *testing.T) {
	c := &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{
		{Name: "lamp", MaxClass: "safe", Digest: digestA},
		{Name: "load", MaxClass: "read", Digest: digestA},
		// A release pinned on first use: no digest, allows nothing here.
		{Name: "tofu", MaxClass: "dangerous"},
	}}
	tests := []struct {
		name, plugin, digest string
		class                Class
		ok                   bool
	}{
		{"install a listed release", "lamp", digestA, "", true},
		{"read under safe", "lamp", digestA, Read, true},
		{"safe at safe", "lamp", digestA, Safe, true},
		{"dangerous above safe", "lamp", digestA, Dangerous, false},
		{"another release", "lamp", digestB, Read, false},
		{"no release", "lamp", "", Read, false},
		{"safe above read", "load", digestA, Safe, false},
		{"not listed", "other", digestA, Read, false},
		{"unpinned grant", "tofu", "", Read, false},
		{"unknown class", "lamp", digestA, Class("root"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PluginWithinCeiling(c, tt.plugin, tt.digest, tt.class)
			if tt.ok != (err == nil) {
				t.Fatalf("PluginWithinCeiling(%s, %q) = %v, want ok %v", tt.plugin, tt.class, err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrBeyondCeiling) {
				t.Fatalf("error %v does not wrap ErrBeyondCeiling", err)
			}
		})
	}
	if err := PluginWithinCeiling(nil, "lamp", digestA, ""); !errors.Is(err, ErrBeyondCeiling) {
		t.Fatalf("a nil ceiling allowed a plugin: %v", err)
	}
	// Two releases of one plugin, from the device and the hub: each its own class.
	two := &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{
		{Name: "lamp", MaxClass: "read", Digest: digestA}, {Name: "lamp", MaxClass: "dangerous", Digest: digestB},
	}}
	if c, _ := PluginReleaseClass(two, "lamp", digestA); c != Read {
		t.Errorf("release A class = %s", c)
	}
	if c, _ := PluginGrantOf(two, "lamp"); c != Dangerous {
		t.Errorf("plugin class = %s", c)
	}
}

func TestCheckPluginGrants(t *testing.T) {
	tests := []struct {
		name   string
		grants []*agentv1.PluginGrant
		ok     bool
	}{
		{"none", nil, true},
		{"valid", []*agentv1.PluginGrant{{Name: "go-lamp", MaxClass: "dangerous", Digest: digestA}, {Name: "a.b_c", MaxClass: "read", Digest: digestB}}, true},
		{"no digest", []*agentv1.PluginGrant{{Name: "lamp", MaxClass: "read"}}, false},
		{"bad digest", []*agentv1.PluginGrant{{Name: "lamp", MaxClass: "read", Digest: strings.Repeat("A", 64)}}, false},
		{"path in name", []*agentv1.PluginGrant{{Name: "../x", MaxClass: "read", Digest: digestA}}, false},
		{"slash in name", []*agentv1.PluginGrant{{Name: "a/b", MaxClass: "read", Digest: digestA}}, false},
		{"empty name", []*agentv1.PluginGrant{{Name: "", MaxClass: "read", Digest: digestA}}, false},
		{"bad class", []*agentv1.PluginGrant{{Name: "lamp", MaxClass: "admin", Digest: digestA}}, false},
		{"no class", []*agentv1.PluginGrant{{Name: "lamp", Digest: digestA}}, false},
		{"twice", []*agentv1.PluginGrant{{Name: "lamp", MaxClass: "read", Digest: digestA}, {Name: "lamp", MaxClass: "safe", Digest: digestB}}, false},
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
