// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
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
