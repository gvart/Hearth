// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Mode is what policy does with the actions of a class: run them, hold them
// for approval, or refuse them.
type Mode string

// Modes.
const (
	ModeAllow   Mode = "allow"
	ModeConfirm Mode = "confirm"
	ModeDeny    Mode = "deny"
)

// ConfigFile is the name of the policy configuration file in the hub's data
// directory. The hub and the CLI commands run on the hub host both read it.
const ConfigFile = "policy.yaml"

// ConfigurableActors are the actor kinds the configuration applies to: the
// operator's clients. The other kinds (agents, joining hubs, cluster members)
// prove themselves with a credential, and their actions are fixed.
var ConfigurableActors = []string{ActorAdmin, ActorWeb, ActorAutomation}

// Config is the operator's policy configuration on top of the rule table.
// The zero Config allows every action the table allows, except dangerous
// actions of automations, which it denies.
type Config struct {
	// Classes is the mode of each class for every configurable actor kind.
	Classes map[Class]Mode `yaml:"classes"`
	// Actors overrides Classes for one actor kind.
	Actors map[string]map[Class]Mode `yaml:"actors"`
	// DangerousAutomations are the ids of the automations allowed to take
	// dangerous actions without approval, whatever the modes say: a grant
	// to one automation is the most specific setting there is.
	DangerousAutomations []string `yaml:"dangerous_automations"`
	// ApprovalTimeout is how long a held action waits for approval before
	// it is denied. Default DefaultApprovalTimeout.
	ApprovalTimeout time.Duration `yaml:"approval_timeout"`
	// ApprovalNotify sends every held action to a notification channel,
	// with a single-use link that approves or denies it.
	ApprovalNotify ApprovalNotify `yaml:"approval_notify"`
}

// ApprovalNotify is where the hub tells someone an action waits for
// approval.
type ApprovalNotify struct {
	// Channel names a channel of the hub's notification channels file;
	// empty sends nothing. The hub checks that it exists.
	Channel string `yaml:"channel"`
	// URL is the hub's web UI as the phone reaches it, as
	// https://hearth.lan:8443, the base of approval links. Empty means the
	// hub's HTTPS address for its first --host.
	URL string `yaml:"url"`
}

// mode returns the mode for an action of class by kind/id, and whether the
// configuration set it rather than the built-in defaults.
func (c Config) mode(class Class, kind, id string) (Mode, bool) {
	if class == Dangerous && kind == ActorAutomation && slices.Contains(c.DangerousAutomations, id) {
		return ModeAllow, true
	}
	if m, ok := c.Actors[kind][class]; ok {
		return m, true
	}
	if m, ok := c.Classes[class]; ok {
		return m, true
	}
	if class == Dangerous && kind == ActorAutomation {
		return ModeDeny, false
	}
	return ModeAllow, false
}

// Validate checks every class, mode and actor kind the configuration names.
func (c Config) Validate() error {
	var errs []error
	checkModes := func(where string, m map[Class]Mode) {
		for class, mode := range m {
			switch class {
			case Read, Safe, Dangerous:
			default:
				errs = append(errs, fmt.Errorf("%s: unknown class %q (want read, safe or dangerous)", where, class))
			}
			switch mode {
			case ModeAllow, ModeConfirm, ModeDeny:
			default:
				errs = append(errs, fmt.Errorf("%s.%s: unknown mode %q (want allow, confirm or deny)", where, class, mode))
			}
		}
	}
	checkModes("classes", c.Classes)
	for kind, m := range c.Actors {
		if !slices.Contains(ConfigurableActors, kind) {
			errs = append(errs, fmt.Errorf("actors: unknown actor kind %q (want one of %s)",
				kind, strings.Join(ConfigurableActors, ", ")))
		}
		checkModes("actors."+kind, m)
	}
	if c.ApprovalTimeout < 0 {
		errs = append(errs, errors.New("approval_timeout must not be negative"))
	}
	if raw := c.ApprovalNotify.URL; raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
			u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, errors.New("approval_notify.url must be the hub's http:// or https:// address, as https://hearth.lan:8443"))
		}
		if c.ApprovalNotify.Channel == "" {
			errs = append(errs, errors.New("approval_notify.url needs approval_notify.channel"))
		}
	}
	return errors.Join(errs...)
}

// LoadConfig reads and validates the configuration file at path. A missing
// file is the zero Config.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read policy config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("policy config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("policy config %s: %w", path, err)
	}
	return c, nil
}
