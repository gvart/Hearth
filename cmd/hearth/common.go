// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/store"
)

const (
	defaultPort     = "7443"
	defaultHTTPPort = "7080"
	dbFile          = "hearth.db"
)

// defaultDataDir is HEARTH_DATA_DIR if set, /var/lib/hearth/<role> for root,
// and the user's XDG data dir otherwise.
func defaultDataDir(role string) string {
	if v := os.Getenv("HEARTH_DATA_DIR"); v != "" {
		return v
	}
	if os.Geteuid() == 0 {
		return filepath.Join("/var/lib/hearth", role)
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "hearth", role)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".hearth", role)
	}
	return filepath.Join(home, ".local", "share", "hearth", role)
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}

// adminActor identifies the local operator in the audit log.
func adminActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

func hostnameOr(fallback string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return fallback
}

// openHubStore opens the hub database for a CLI command on the hub host. On a
// standalone hub it opens the file directly, as always. On a cluster member,
// reads still come from the local file but writes go through the running
// hub's control socket and so through Raft: writing the local file directly
// would silently diverge from the other hubs.
func openHubStore(ctx context.Context, dataDir string) (*store.Store, error) {
	path := filepath.Join(dataDir, dbFile)
	if !cluster.IsMember(dataDir) {
		return store.Open(ctx, path)
	}
	cc, err := cluster.DialControl(dataDir)
	if err != nil {
		return nil, err
	}
	return store.Open(ctx, path, store.WithoutUpgrade(),
		store.WithApplier(func(*store.Store) store.Applier { return cc }))
}
