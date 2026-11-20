// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"maps"
	"sync/atomic"
)

// Holding returns an engine like e that holds for approval the requests of
// class by actor kind that e would allow. What e denies stays denied, and
// without approvals a held request is denied. e itself does not change.
func (e *Engine) Holding(kind string, class Class) *Engine {
	cfg := e.Config()
	if m, _ := cfg.mode(class, kind, ""); m != ModeAllow {
		return e
	}
	held := *e
	cfg.Actors = maps.Clone(cfg.Actors)
	if cfg.Actors == nil {
		cfg.Actors = map[string]map[Class]Mode{}
	}
	modes := maps.Clone(cfg.Actors[kind])
	if modes == nil {
		modes = map[Class]Mode{}
	}
	modes[class] = ModeConfirm
	cfg.Actors[kind] = modes
	held.cfg = &atomic.Pointer[Config]{}
	held.cfg.Store(&cfg)
	return &held
}
