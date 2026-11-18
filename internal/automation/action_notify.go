// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"

	"github.com/gvart/hearth/internal/policy"
)

// Notifier sends to the notification channels configured on the hub:
// *notify.Notifier.
type Notifier interface {
	Has(channel string) bool
	Send(ctx context.Context, channel, title, message string) error
}

// notifyAction sends a message to a notification channel. The channel is
// named, never addressed: its credentials stay in the hub's channels file.
type notifyAction struct {
	notifier Notifier
	channel  string
	title    Text
	message  Text
}

func buildNotify(p Params, n Notifier) (Action, error) {
	var cfg struct {
		Channel string `yaml:"channel"`
		Title   string `yaml:"title"`
		Message string `yaml:"message"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Channel == "" {
		return nil, errors.New("channel is required: the name of a channel in the hub's notification channels file")
	}
	// Without a notifier (hearth automation plan) the channel cannot be
	// checked; the hub checks it when it loads the file.
	if n != nil && !n.Has(cfg.Channel) {
		return nil, fmt.Errorf("no notification channel %q on this hub (see hearth hub --notify-config)", cfg.Channel)
	}
	if cfg.Message == "" {
		return nil, errors.New("message is required")
	}
	title, err := p.Text(cfg.Title, "title")
	if err != nil {
		return nil, err
	}
	msg, err := p.Text(cfg.Message, "message")
	if err != nil {
		return nil, err
	}
	return &notifyAction{notifier: n, channel: cfg.Channel, title: title, message: msg}, nil
}

func (a *notifyAction) Describe() string {
	return fmt.Sprintf("notify %s: %q", a.channel, a.message)
}

func (a *notifyAction) Policy() policy.Action { return policy.AutomationNotify }
func (a *notifyAction) Target() Text          { return Literal(a.channel) }
func (a *notifyAction) texts() []Text         { return []Text{a.title, a.message} }

func (a *notifyAction) Run(ctx context.Context, ev Event) error {
	if a.notifier == nil {
		return errors.New("this hub sends no notifications")
	}
	title, err := a.title.Render(ev)
	if err != nil {
		return err
	}
	msg, err := a.message.Render(ev)
	if err != nil {
		return err
	}
	return a.notifier.Send(ctx, a.channel, title, msg)
}
