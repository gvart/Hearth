// SPDX-License-Identifier: AGPL-3.0-only

// Package plugins runs exec plugins: integrations written in any language
// that the hub starts as child processes and talks to in JSON lines over
// stdin and stdout (protocol version 1, see docs/plugins.md).
//
// A plugin runs only when the operator names its manifest in the hub's
// flags. Its process is started without a shell, with a clean environment,
// and contained: a crash, a hang, garbage output or a flood stops and
// restarts it with backoff, never the hub. Every command a plugin offers is
// declared, with its policy class, in the manifest, and runs only through
// policy.
package plugins

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
)

// ProtocolVersion is the version of the plugin protocol this hub speaks.
const ProtocolVersion = 1

// Capabilities a manifest may request.
const (
	// CapDiscover lets the plugin report devices and their entities.
	CapDiscover = "discover"
	// CapState lets the plugin push entity states.
	CapState = "state"
	// CapCommand lets the hub send the plugin the commands it declares.
	CapCommand = "command"
)

var knownCaps = []string{CapDiscover, CapState, CapCommand}

// maxManifest bounds a manifest file.
const maxManifest = 64 << 10

// idRE is what plugin, device, entity and command names look like.
var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Manifest describes an exec plugin: what to run and what it may do. The
// operator writes or reviews it; nothing the plugin's process prints can
// change it.
type Manifest struct {
	// Protocol is the plugin protocol version the plugin speaks: 1.
	Protocol int `yaml:"protocol"`
	// Name identifies the plugin: letters, digits, '.', '_' and '-'.
	Name string `yaml:"name"`
	// Version is the plugin's own version, shown and audited.
	Version string `yaml:"version"`
	// Command is the program to run: a path relative to the manifest's
	// directory or absolute, or a bare name looked up in the hub's PATH
	// (such as python3). It is never run through a shell.
	Command string `yaml:"command"`
	// Args are the program's arguments, as is.
	Args []string `yaml:"args"`
	// Env is the plugin's environment, on top of PATH and HEARTH_PLUGIN.
	// Nothing of the hub's own environment is passed.
	Env map[string]string `yaml:"env"`
	// Capabilities are what the plugin may do: discover, state, command.
	Capabilities []string `yaml:"capabilities"`
	// Commands are the commands the plugin offers, each with its policy
	// class. The hub sends no other command.
	Commands []CommandSpec `yaml:"commands"`

	// Dir is the manifest's directory: the plugin's working directory, and
	// the base of a relative Command.
	Dir string `yaml:"-"`
}

// CommandSpec is a command a plugin declares.
type CommandSpec struct {
	Name string `yaml:"name" json:"name"`
	// Class is the command's policy class: read, safe or dangerous.
	Class       policy.Class `yaml:"class" json:"class"`
	Description string       `yaml:"description" json:"description,omitempty"`
}

// Has reports whether the manifest requests capability c.
func (m Manifest) Has(c string) bool { return slices.Contains(m.Capabilities, c) }

// command returns the declared command named name.
func (m Manifest) command(name string) (CommandSpec, bool) {
	i := slices.IndexFunc(m.Commands, func(c CommandSpec) bool { return c.Name == name })
	if i < 0 {
		return CommandSpec{}, false
	}
	return m.Commands[i], true
}

// Validate checks the manifest.
func (m Manifest) Validate() error {
	var errs []error
	if m.Protocol != ProtocolVersion {
		errs = append(errs, fmt.Errorf("protocol must be %d, not %d", ProtocolVersion, m.Protocol))
	}
	if !idRE.MatchString(m.Name) {
		errs = append(errs, fmt.Errorf("name %q: want 1-64 letters, digits, '.', '_' or '-'", m.Name))
	}
	if m.Command == "" {
		errs = append(errs, errors.New("command is required"))
	}
	for k := range m.Env {
		if k == "" || strings.ContainsAny(k, "=\x00") || k == "PATH" || k == "HEARTH_PLUGIN" {
			errs = append(errs, fmt.Errorf("env: invalid or reserved name %q", k))
		}
	}
	for _, c := range m.Capabilities {
		if !slices.Contains(knownCaps, c) {
			errs = append(errs, fmt.Errorf("capabilities: unknown %q (want %s)", c, strings.Join(knownCaps, ", ")))
		}
	}
	if len(m.Commands) > 0 && !m.Has(CapCommand) {
		errs = append(errs, errors.New("commands need the command capability"))
	}
	seen := map[string]bool{}
	for _, c := range m.Commands {
		if !idRE.MatchString(c.Name) {
			errs = append(errs, fmt.Errorf("commands: invalid name %q", c.Name))
		}
		if seen[c.Name] {
			errs = append(errs, fmt.Errorf("commands: %q declared twice", c.Name))
		}
		seen[c.Name] = true
		if _, ok := commandAction(c.Class); !ok {
			errs = append(errs, fmt.Errorf("commands.%s: class %q (want read, safe or dangerous)", c.Name, c.Class))
		}
	}
	return errors.Join(errs...)
}

// commandAction is the policy action of a command of class.
func commandAction(c policy.Class) (policy.Action, bool) {
	switch c {
	case policy.Read:
		return policy.PluginCommandRead, true
	case policy.Safe:
		return policy.PluginCommandSafe, true
	case policy.Dangerous:
		return policy.PluginCommandDangerous, true
	}
	return "", false
}

// LoadManifest reads and validates the manifest file at path. A manifest
// anyone but its owner can write is refused: it says what the hub runs.
func LoadManifest(path string) (Manifest, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest %s: %w", path, err)
	}
	f, err := os.Open(abs) //nolint:gosec // the operator names the manifest
	if err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := checkNotShared(f); err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest %s: %w", abs, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxManifest+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest %s: %w", abs, err)
	}
	if len(b) > maxManifest {
		return Manifest{}, fmt.Errorf("plugin manifest %s: larger than %d bytes", abs, maxManifest)
	}
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest %s: %w", abs, err)
	}
	m.Dir = filepath.Dir(abs)
	if err := m.Validate(); err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest %s: %w", abs, err)
	}
	return m, nil
}

// checkNotShared refuses a file its group or others can write.
func checkNotShared(f *os.File) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("writable by group or others (mode %v): chmod go-w it", fi.Mode().Perm())
	}
	return nil
}
