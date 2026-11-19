// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"testing"
)

func TestHolding(t *testing.T) {
	webDangerous := Request{ActorKind: ActorWeb, ActorID: "10.0.0.1", Action: AutomationApply, Target: "nightly"}
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "allowed becomes held", cfg: Config{}, want: Confirm},
		{
			name: "held stays held",
			cfg:  Config{Classes: map[Class]Mode{Dangerous: ModeConfirm}},
			want: Confirm,
		},
		{
			name: "denied stays denied",
			cfg:  Config{Actors: map[string]map[Class]Mode{ActorWeb: {Dangerous: ModeDeny}}},
			want: Deny,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewWithConfig(nil, nil, tc.cfg)
			before, _ := e.Check(webDangerous)
			if got, _ := e.Holding(ActorWeb, Dangerous).Check(webDangerous); got != tc.want {
				t.Errorf("decision %s, want %s", got, tc.want)
			}
			if after, _ := e.Check(webDangerous); after != before {
				t.Errorf("the original engine changed from %s to %s", before, after)
			}
		})
	}
}

func TestHoldingLeavesOtherActorsAndClasses(t *testing.T) {
	cfg := Config{Actors: map[string]map[Class]Mode{ActorMCP: {Dangerous: ModeAllow}}}
	e := NewWithConfig(nil, nil, cfg).Holding(ActorWeb, Dangerous)
	mcp := Request{ActorKind: ActorMCP, ActorID: "client", Action: AutomationApply, Target: "nightly"}
	if got, _ := e.Check(mcp); got != Allow {
		t.Errorf("another actor kind decided %s, want allow", got)
	}
}

func TestGrantedDangerous(t *testing.T) {
	e := NewWithConfig(nil, nil, Config{DangerousAutomations: []string{"nightly"}})
	if !e.GrantedDangerous("nightly") {
		t.Error("nightly is granted")
	}
	if e.GrantedDangerous("other") {
		t.Error("other is not granted")
	}
}
