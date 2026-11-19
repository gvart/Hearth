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

func (manualTrigger) Sample() map[string]any { return map[string]any{} }

func (manualTrigger) Watch(ctx context.Context, _ FireFunc) error {
	<-ctx.Done()
	return nil
}

// logAction writes a message to the hub log.
type logAction struct {
	message Text
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
	msg, err := p.Text(cfg.Message, "message")
	if err != nil {
		return nil, err
	}
	return &logAction{message: msg, log: logger}, nil
}

func (a *logAction) Describe() string { return fmt.Sprintf("log %q", a.message) }

func (a *logAction) texts() []Text { return []Text{a.message} }

func (a *logAction) Policy() policy.Action { return policy.AutomationLog }

func (a *logAction) Target() Text { return Literal("") }

func (a *logAction) Run(ctx context.Context, ev Event) error {
	msg, err := a.message.Render(ctx, ev)
	if err != nil {
		return err
	}
	a.log.InfoContext(ctx, "automation log", "message", msg, "trigger", ev.TriggerID)
	return nil
}
