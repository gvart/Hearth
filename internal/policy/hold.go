// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"maps"
	"slices"
)

// GrantedDangerous reports whether the configuration lets the automation id
// take dangerous actions without approval. The grant follows the id, not the
// file's content: whoever can rewrite that file inherits it.
func (e *Engine) GrantedDangerous(id string) bool {
	return slices.Contains(e.cfg.DangerousAutomations, id)
}

// Holding returns an engine like e that holds for approval the requests of
// class by actor kind that e would allow. What e denies stays denied, and
// without approvals a held request is denied. e itself does not change.
func (e *Engine) Holding(kind string, class Class) *Engine {
	if m, _ := e.cfg.mode(class, kind, ""); m != ModeAllow {
		return e
	}
	held := *e
	held.cfg.Actors = maps.Clone(e.cfg.Actors)
	if held.cfg.Actors == nil {
		held.cfg.Actors = map[string]map[Class]Mode{}
	}
	modes := maps.Clone(held.cfg.Actors[kind])
	if modes == nil {
		modes = map[Class]Mode{}
	}
	modes[class] = ModeConfirm
	held.cfg.Actors[kind] = modes
	return &held
}
