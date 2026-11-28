// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

// The plugins a hub installed from a registry live in its data dir, under
// RegistryDir, one directory per plugin:
//
//	<name>/release.json        what was installed, from where, by whom
//	<name>/<sha256>/plugin.yaml the manifest, from the signed index entry
//	<name>/<sha256>/plugin.wasm the module, checked against that SHA-256
//
// Each release has a directory of its own, so a plugin running one release
// never reads another's module. The files are the hub user's, 0600 in 0700
// directories, so the trust checks of LoadManifest and of every start hold.
// Each hub of a cluster runs the plugins installed on it, as it runs those
// of its own --plugin flags.

// RegistryDir is the directory of a hub's data dir that holds the plugins
// installed from a registry.
const RegistryDir = "registry-plugins"

// releaseFile is an installed plugin's record.
const releaseFile = "release.json"

// Installed is a plugin installed from a registry.
type Installed struct {
	// Entry is the index entry it was installed from: its manifest too.
	Entry IndexEntry `json:"entry"`
	// Source is the index it came from.
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installed_at"`
	InstalledBy string    `json:"installed_by"`
}

// InstalledStore is the plugins installed under Dir.
type InstalledStore struct {
	Dir string
}

// NewInstalledStore returns the plugins installed in dataDir.
func NewInstalledStore(dataDir string) InstalledStore {
	return InstalledStore{Dir: filepath.Join(dataDir, RegistryDir)}
}

// List returns every installed plugin, by name. One whose record cannot be
// read is left out, and its error returned with the others'.
func (s InstalledStore) List() ([]Installed, error) {
	ents, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list installed plugins: %w", err)
	}
	var (
		out  []Installed
		errs []error
	)
	for _, d := range ents {
		if !d.IsDir() || !idRE().MatchString(d.Name()) {
			continue
		}
		in, err := s.read(d.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, in)
	}
	return out, errors.Join(errs...)
}

// Get returns the installed plugin name.
func (s InstalledStore) Get(name string) (Installed, bool, error) {
	if !idRE().MatchString(name) {
		return Installed{}, false, nil
	}
	in, err := s.read(name)
	if errors.Is(err, fs.ErrNotExist) {
		return Installed{}, false, nil
	}
	return in, err == nil, err
}

func (s InstalledStore) read(name string) (Installed, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, name, releaseFile))
	if err != nil {
		return Installed{}, fmt.Errorf("installed plugin %s: %w", name, err)
	}
	var in Installed
	if err := json.Unmarshal(b, &in); err != nil {
		return Installed{}, fmt.Errorf("installed plugin %s: %s: %w", name, releaseFile, err)
	}
	if in.Entry.Name != name || !ValidSHA256(in.Entry.SHA256) {
		return Installed{}, fmt.Errorf("installed plugin %s: %s names another plugin", name, releaseFile)
	}
	return in, nil
}

// releaseDir is the directory of an installed release.
func (s InstalledStore) releaseDir(e IndexEntry) string {
	return filepath.Join(s.Dir, e.Name, e.SHA256)
}

// Put installs module as e's, from source, by by at now, replacing the
// release installed before, if any. module must be the bytes e pins.
func (s InstalledStore) Put(e IndexEntry, module []byte, source, by string, now time.Time) error {
	if err := e.Validate(); err != nil {
		return err
	}
	dir := filepath.Join(s.Dir, e.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("install plugin %s: %w", e.Name, err)
	}
	// Tighten what MkdirAll made under a wider umask, or found.
	for _, d := range []string{s.Dir, dir} {
		if err := os.Chmod(d, 0o700); err != nil {
			return fmt.Errorf("install plugin %s: %w", e.Name, err)
		}
	}
	tmp, err := os.MkdirTemp(dir, ".install-*")
	if err != nil {
		return fmt.Errorf("install plugin %s: %w", e.Name, err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	man, err := yaml.Marshal(e.Manifest(""))
	if err != nil {
		return fmt.Errorf("install plugin %s: %w", e.Name, err)
	}
	for f, b := range map[string][]byte{moduleFile: module, manifestFile: man} {
		if err := os.WriteFile(filepath.Join(tmp, f), b, 0o600); err != nil {
			return fmt.Errorf("install plugin %s: %w", e.Name, err)
		}
	}
	if err := os.Chmod(tmp, 0o700); err != nil {
		return fmt.Errorf("install plugin %s: %w", e.Name, err)
	}
	rel := s.releaseDir(e)
	if err := os.RemoveAll(rel); err != nil {
		return fmt.Errorf("install plugin %s: %w", e.Name, err)
	}
	if err := os.Rename(tmp, rel); err != nil {
		return fmt.Errorf("install plugin %s: %w", e.Name, err)
	}
	rec, err := json.MarshalIndent(Installed{Entry: e, Source: source, InstalledAt: now.UTC(), InstalledBy: by}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, releaseFile), rec); err != nil {
		return fmt.Errorf("install plugin %s: %w", e.Name, err)
	}
	// The release it replaces goes; the running plugin is stopped, or
	// fails to restart, until the hub starts the new one.
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, d := range ents {
		if d.IsDir() && d.Name() != e.SHA256 && !strings.HasPrefix(d.Name(), ".install-") {
			_ = os.RemoveAll(filepath.Join(dir, d.Name()))
		}
	}
	return nil
}

// writeFileAtomic writes b to path, 0600, through a file renamed in place.
func writeFileAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Remove uninstalls plugin name.
func (s InstalledStore) Remove(name string) error {
	if _, ok, err := s.Get(name); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("plugin %s: %w", name, ErrNotInstalled)
		}
		return err
	}
	dir := filepath.Join(s.Dir, name)
	// The record goes first: a half-removed plugin is not installed.
	if err := os.Remove(filepath.Join(dir, releaseFile)); err != nil {
		return fmt.Errorf("remove plugin %s: %w", name, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove plugin %s: %w", name, err)
	}
	return nil
}

// Manifests loads the manifest of every installed plugin, with the trust
// checks of LoadManifest, and checks it is the one its record holds. A
// plugin that fails is left out, its error by name.
func (s InstalledStore) Manifests() ([]Manifest, map[string]error) {
	list, err := s.List()
	errs := map[string]error{}
	if err != nil {
		errs[""] = err
	}
	var out []Manifest
	for _, in := range list {
		m, err := LoadManifest(filepath.Join(s.releaseDir(in.Entry), manifestFile))
		if err == nil && (m.Version != in.Entry.Version || m.SHA256 != in.Entry.SHA256 || !m.IsWasm()) {
			err = fmt.Errorf("plugin %s: its manifest is not the release installed", in.Entry.Name)
		}
		if err != nil {
			errs[in.Entry.Name] = err
			continue
		}
		out = append(out, m)
	}
	return out, errs
}

// RegistrySync keeps a Manager running the plugins installed in Store:
// it starts the ones installed, restarts the ones updated and stops the ones
// removed, whether by the hub's API or by `hearth plugin` in another process.
type RegistrySync struct {
	Store   InstalledStore
	Manager *Manager
	Log     *slog.Logger

	mu   sync.Mutex
	errs map[string]string
}

// Sync applies what is installed now.
func (r *RegistrySync) Sync(ctx context.Context) {
	manifests, errs := r.Store.Manifests()
	for name, err := range r.Manager.Reconcile(manifests) {
		errs[name] = err
	}
	out := make(map[string]string, len(errs))
	for name, err := range errs {
		out[name] = err.Error()
	}
	r.mu.Lock()
	changed := !maps.Equal(out, r.errs)
	r.errs = out
	r.mu.Unlock()
	if changed && r.Log != nil {
		for name, e := range out {
			r.Log.WarnContext(ctx, "installed plugin not run", "plugin", name, "err", e)
		}
	}
}

// Errors are why installed plugins do not run, by name ("" for the store
// itself).
func (r *RegistrySync) Errors() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.errs)
}

// Run syncs every interval until ctx is done.
func (r *RegistrySync) Run(ctx context.Context, every time.Duration) error {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r.Sync(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
