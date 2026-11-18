// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gvart/hearth/internal/policy"
)

// Builtin returns the built-in kinds: the manual trigger and the log action,
// which writes to logger. Real triggers and actions are added on top.
func Builtin(logger *slog.Logger) Kinds {
	return Kinds{
		Triggers:   map[string]Builder[Trigger]{"manual": buildManual},
		Conditions: map[string]Builder[Condition]{},
		Actions: map[string]Builder[Action]{
			"log": func(p Params) (Action, error) { return buildLog(p, logger) },
		},
	}
}

// manualTrigger fires only when asked to with Runtime.Fire.
type manualTrigger struct{}

func buildManual(p Params) (Trigger, error) {
	var cfg struct{}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	return manualTrigger{}, nil
}

func (manualTrigger) Describe() string { return "fires when run by hand" }

func (manualTrigger) Watch(ctx context.Context, _ func()) error {
	<-ctx.Done()
	return nil
}

// logAction writes a message to the hub log.
type logAction struct {
	message string
	log     *slog.Logger
}

func buildLog(p Params, logger *slog.Logger) (Action, error) {
	var cfg struct {
		Message string `yaml:"message"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Message == "" {
		return nil, errors.New("message is required")
	}
	return &logAction{message: cfg.Message, log: logger}, nil
}

func (a *logAction) Describe() string { return fmt.Sprintf("log %q", a.message) }

func (a *logAction) Policy() policy.Action { return policy.AutomationLog }

func (a *logAction) Target() string { return "" }

func (a *logAction) Run(ctx context.Context, ev Event) error {
	a.log.InfoContext(ctx, "automation log", "message", a.message, "trigger", ev.TriggerID)
	return nil
}
