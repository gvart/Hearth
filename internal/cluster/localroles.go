// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// rolesFile keeps an AP member's roles, as promote and demote set them, in
// DataDir/raft: they survive a restart.
const rolesFile = "roles"

// LocalRoles is an AP member's role state: its roles, and the role change
// still under way.
type LocalRoles struct {
	Roles RoleSet `json:"roles"`
	// Syncing: promoted to storage, the member is still copying the rows of
	// its buckets from the others; it serves no reads until it has.
	Syncing bool `json:"syncing,omitempty"`
	// Draining: a demotion from storage is handing this member's rows off;
	// it keeps the role until every row it holds has N other copies.
	Draining bool `json:"draining,omitempty"`
}

// LoadLocalRoles reads the roles recorded in dataDir, within allowed (the
// host's --allow-roles, the ceiling): a role allowed no more is dropped,
// with a warning. Without a record a hub takes HubRoles within allowed. A
// member left with neither storage nor master could not gossip: an error.
func LoadLocalRoles(dataDir string, allowed RoleSet, log *slog.Logger) (LocalRoles, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	lr := LocalRoles{Roles: HubRoles}
	b, err := os.ReadFile(filepath.Join(dataDir, RaftDir, rolesFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return LocalRoles{}, fmt.Errorf("read roles: %w", err)
	default:
		if err := json.Unmarshal(b, &lr); err != nil {
			return LocalRoles{}, fmt.Errorf("read roles %s: %w", filepath.Join(dataDir, RaftDir, rolesFile), err)
		}
		if dropped := lr.Roles &^ allowed; dropped != 0 {
			log.Warn("dropping roles this host no longer allows (--allow-roles)", "roles", dropped.String(),
				"allowed", allowed.String())
		}
	}
	lr.Roles &= allowed
	if !lr.Roles.Has(RoleStorage) {
		lr.Syncing, lr.Draining = false, false
	}
	if !lr.Roles.Gossips() {
		return LocalRoles{}, fmt.Errorf("--allow-roles %s leaves this hub neither storage nor master: "+
			"a hub of an AP cluster takes at least one of them", allowed)
	}
	return lr, nil
}

// saveLocalRoles records lr in dataDir.
func saveLocalRoles(dataDir string, lr LocalRoles) error {
	b, err := json.Marshal(lr)
	if err != nil {
		return err
	}
	dir := filepath.Join(dataDir, RaftDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("record roles: %w", err)
	}
	path := filepath.Join(dir, rolesFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("record roles: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("record roles: %w", err)
	}
	return nil
}
