// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"fmt"
	"slices"

	"github.com/gvart/hearth/internal/policy"
)

// Change is an install or an update from a registry, decided by policy
// before anything is written: the entry to install, and the release it
// replaces.
type Change struct {
	// Action is policy.PluginRegistryInstall or policy.PluginRegistryUpdate.
	Action policy.Action
	Entry  IndexEntry
	// Previous is the release installed now, for an update.
	Previous *Installed
	// Source is the index the entry is from.
	Source string
}

// PlanInstall is the install of version of plugin name (the newest if
// empty) from idx, read from source. A plugin installed already is updated
// instead, never installed again.
func PlanInstall(idx *Index, source string, st InstalledStore, name, version string) (Change, error) {
	if _, ok, err := st.Get(name); err != nil || ok {
		if err == nil {
			err = fmt.Errorf("plugin %s: %w: update it instead", name, ErrInstalled)
		}
		return Change{}, err
	}
	e, err := idx.Entry(name, version)
	if err != nil {
		return Change{}, err
	}
	return Change{Action: policy.PluginRegistryInstall, Entry: e, Source: source}, nil
}

// PlanUpdate is the update of installed plugin name to version (the newest
// if empty) from idx. An older version than the one installed is refused
// unless allowDowngrade; so is the version installed, and the same version
// with another module, which only a changed index can offer.
func PlanUpdate(idx *Index, source string, st InstalledStore, name, version string, allowDowngrade bool) (Change, error) {
	in, ok, err := st.Get(name)
	if err != nil {
		return Change{}, err
	}
	if !ok {
		return Change{}, fmt.Errorf("plugin %s: %w", name, ErrNotInstalled)
	}
	e, err := idx.Entry(name, version)
	if err != nil {
		return Change{}, err
	}
	switch c := CompareVersions(e.Version, in.Entry.Version); {
	case c == 0 && e.SHA256 == in.Entry.SHA256:
		return Change{}, fmt.Errorf("plugin %s %s: %w", name, e.Version, ErrUpToDate)
	case c == 0:
		return Change{}, fmt.Errorf("plugin %s %s: %w; refused", name, e.Version, ErrModuleChanged)
	case c < 0 && !allowDowngrade:
		return Change{}, fmt.Errorf("plugin %s: %s is older than %s, installed: %w (ask for the downgrade explicitly)",
			name, e.Version, in.Entry.Version, ErrDowngrade)
	}
	return Change{Action: policy.PluginRegistryUpdate, Entry: e, Previous: &in, Source: source}, nil
}

// Confirmed checks that c installs what the caller reviewed: version,
// sha256 and the entry's digest, each if given. Otherwise the index changed
// meanwhile.
func (c Change) Confirmed(version, sha256, digest string) error {
	if (version != "" && CompareVersions(version, c.Entry.Version) != 0) || (sha256 != "" && sha256 != c.Entry.SHA256) ||
		(digest != "" && digest != c.Entry.Digest()) {
		return fmt.Errorf("plugin %s: %w", c.Entry.Name, ErrIndexChanged)
	}
	return nil
}

// Request is c as a policy request: its detail says what would run, with
// what host access, from where.
func (c Change) Request() policy.Request {
	d := map[string]any{
		"plugin": c.Entry.Name, "version": c.Entry.Version, "sha256": c.Entry.SHA256, "digest": c.Entry.Digest(), "source": c.Source,
		"runtime": c.Entry.Runtime, "memory": c.Entry.MemoryMiB(),
		"capabilities": nonNilStrings(c.Entry.Capabilities), "commands": CommandList(c.Entry.Commands),
		"http_allow": HTTPAllow(c.Entry.Host),
	}
	if c.Previous != nil {
		d["previous_version"] = c.Previous.Entry.Version
		d["previous_sha256"] = c.Previous.Entry.SHA256
	}
	return policy.Request{Action: c.Action, Target: c.Entry.Name, Detail: d}
}

// RemoveRequest is the removal of installed plugin in as a policy request.
func RemoveRequest(in Installed) policy.Request {
	return policy.Request{
		Action: policy.PluginRegistryRemove, Target: in.Entry.Name,
		Detail: map[string]any{"plugin": in.Entry.Name, "version": in.Entry.Version, "sha256": in.Entry.SHA256},
	}
}

// HTTPAllow are the hosts g lets a plugin reach over HTTP; none if empty.
func HTTPAllow(g HostGrants) []string {
	if g.HTTP == nil {
		return []string{}
	}
	return slices.Clone(g.HTTP.Allow)
}

// CommandList is commands as name:class.
func CommandList(commands []CommandSpec) []string {
	out := make([]string, 0, len(commands))
	for _, c := range commands {
		out = append(out, c.Name+":"+string(c.Class))
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Update is a newer version of an installed plugin that an index offers.
type Update struct {
	Name, Installed, Available string
}

// Updates are the installed plugins idx offers a newer version of. An
// older version is never one: a downgrade is only ever asked for.
func Updates(idx *Index, installed []Installed) []Update {
	var out []Update
	for _, in := range installed {
		if e, ok := idx.Latest(in.Entry.Name); ok && CompareVersions(e.Version, in.Entry.Version) > 0 {
			out = append(out, Update{Name: in.Entry.Name, Installed: in.Entry.Version, Available: e.Version})
		}
	}
	return out
}
