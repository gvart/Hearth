// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// devicePluginsSchema is the schema version whose migration (00040) added
// device_plugins. Before it no plugin can be uploaded for devices.
const devicePluginsSchema = 40

// DevicePlugin is an exec plugin uploaded for the agents of one platform
// (#223).
type DevicePlugin struct {
	// ID is DevicePluginID(Name, OS, Arch).
	ID   string
	Name string
	// OS and Arch are the platform, as Go names them: linux, arm64.
	OS, Arch string
	Version  string
	// SHA256 pins the program, in hex, and Size is its length in bytes.
	SHA256 string
	Size   int64
	// Manifest is JSON of what the agent needs to run it: args,
	// capabilities and commands.
	Manifest json.RawMessage
	// Holder is the hub whose data dir holds the program.
	Holder     string
	UploadedAt time.Time
	UploadedBy string
}

// DevicePluginID is the id of plugin name for platform os/arch.
func DevicePluginID(name, os, arch string) string {
	return naturalID("device_plugins", []byte(name+"\x00"+os+"\x00"+arch))
}

// SetDevicePlugin adds the plugin of a platform, or replaces it.
type SetDevicePlugin struct {
	Stamp
	ID         string `json:"id"`
	Name       string `json:"name"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Version    string `json:"version"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Manifest   string `json:"manifest"`
	Holder     string `json:"holder"`
	UploadedAt int64  `json:"uploaded_at"`
	UploadedBy string `json:"uploaded_by"`
}

// Op implements Command.
func (SetDevicePlugin) Op() string { return "set_device_plugin" }

func (SetDevicePlugin) minSchema() int64 { return devicePluginsSchema }

func (c SetDevicePlugin) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.put(ctx, "device_plugins", row{
		"id": c.ID, "name": c.Name, "os": c.OS, "arch": c.Arch, "version": c.Version, "sha256": c.SHA256,
		"size": c.Size, "manifest": c.Manifest, "holder": c.Holder, "uploaded_at": c.UploadedAt, "uploaded_by": c.UploadedBy,
	})
}

// RemoveDevicePlugin deletes the plugin of a platform. It fails with
// ErrNotFound if there is none with ID.
type RemoveDevicePlugin struct {
	Stamp
	ID string `json:"id"`
}

// Op implements Command.
func (RemoveDevicePlugin) Op() string { return "remove_device_plugin" }

func (RemoveDevicePlugin) minSchema() int64 { return devicePluginsSchema }

func (c RemoveDevicePlugin) apply(ctx context.Context, w *writer) (Result, error) {
	return deleteRow(ctx, w, "device_plugins", c.ID)
}

// DevicePlugins is the repository of the plugins uploaded for devices.
type DevicePlugins struct{ s *Store }

// DevicePlugins returns the device plugins repository.
func (s *Store) DevicePlugins() DevicePlugins { return DevicePlugins{s: s} }

func (r DevicePlugins) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < devicePluginsSchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; upgrade every hub of the cluster first",
			ErrSchemaTooOld, devicePluginsSchema, v)
	}
	return nil
}

// Set stores p, replacing the plugin of its name and platform. Its ID is
// set from them. Before schema 40 it fails with ErrSchemaTooOld.
func (r DevicePlugins) Set(ctx context.Context, p DevicePlugin) error {
	if p.Name == "" || p.OS == "" || p.Arch == "" || p.SHA256 == "" || !json.Valid(p.Manifest) {
		return errors.New("set device plugin: name, platform, SHA-256 and a JSON manifest are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("set device plugin %s: %w", p.Name, err)
	}
	if _, err := r.s.apply(ctx, SetDevicePlugin{
		ID: DevicePluginID(p.Name, p.OS, p.Arch), Name: p.Name, OS: p.OS, Arch: p.Arch, Version: p.Version,
		SHA256: p.SHA256, Size: p.Size, Manifest: string(p.Manifest), Holder: p.Holder,
		UploadedAt: toMillis(p.UploadedAt), UploadedBy: p.UploadedBy,
	}); err != nil {
		return fmt.Errorf("set device plugin %s: %w", p.Name, err)
	}
	return nil
}

// Remove deletes the plugin id, or fails with ErrNotFound. Before schema 40
// it fails with ErrSchemaTooOld.
func (r DevicePlugins) Remove(ctx context.Context, id string) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("remove device plugin %s: %w", id, err)
	}
	if _, err := r.s.apply(ctx, RemoveDevicePlugin{ID: id}); err != nil {
		return fmt.Errorf("remove device plugin %s: %w", id, err)
	}
	return nil
}

// List returns every plugin, ordered by name and platform. Before the schema
// that added them there are none.
func (r DevicePlugins) List(ctx context.Context) ([]DevicePlugin, error) {
	ok, err := atSchema(ctx, r.s.db, devicePluginsSchema)
	if err != nil {
		return nil, fmt.Errorf("list device plugins: %w", err)
	}
	if !ok {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx, `SELECT id, name, os, arch, version, sha256, size, manifest, holder, uploaded_at, uploaded_by
		FROM device_plugins WHERE _deleted = 0 ORDER BY name, os, arch`)
	if err != nil {
		return nil, fmt.Errorf("list device plugins: %w", err)
	}
	defer rows.Close()
	var out []DevicePlugin
	for rows.Next() {
		var (
			p        DevicePlugin
			manifest string
			ms       int64
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.OS, &p.Arch, &p.Version, &p.SHA256, &p.Size, &manifest, &p.Holder, &ms, &p.UploadedBy); err != nil {
			return nil, fmt.Errorf("list device plugins: %w", err)
		}
		p.Manifest, p.UploadedAt = json.RawMessage(manifest), fromMillis(ms)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list device plugins: %w", err)
	}
	return out, nil
}
