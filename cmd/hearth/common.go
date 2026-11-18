// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	defaultPort     = "7443"
	defaultHTTPPort = "7080"
	dbFile          = "hearth.db"
	// metricsDBFile holds the hub's own host metrics; not replicated.
	metricsDBFile = "metrics.db"
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

// loadPolicyConfig reads the policy file of the hub data directory: the
// hub's, and the CLI's on the hub host, so both decide alike.
func loadPolicyConfig(dataDir string) (policy.Config, error) {
	return policy.LoadConfig(filepath.Join(dataDir, policy.ConfigFile))
}

// cliPolicy is the policy engine of a CLI command on the hub host: the
// hub's configuration, holding actions in st for the command to wait on.
func cliPolicy(dataDir string, st *store.Store) (*policy.Engine, error) {
	cfg, err := loadPolicyConfig(dataDir)
	if err != nil {
		return nil, err
	}
	return policy.NewWithConfig(st.Audit(), st.Approvals(), cfg), nil
}

// adminDo runs fn as the local operator through the hub's policy. An action
// the configuration holds waits here for approval. A dry run audits and
// prints the decision, runs nothing and returns false.
func adminDo(ctx context.Context, dataDir string, st *store.Store, out io.Writer, dryRun bool,
	req policy.Request, fn func(context.Context) error,
) (bool, error) {
	pol, err := cliPolicy(dataDir, st)
	if err != nil {
		return false, err
	}
	req.ActorKind, req.ActorID, req.DryRun = policy.ActorAdmin, adminActor(), dryRun
	req.OnHold = func(id string, expires time.Time) {
		_, _ = fmt.Fprintf(out, "This action needs approval: waiting until %s for `hearth approval approve %s` "+
			"(or deny)...\n", expires.Local().Format(time.TimeOnly), id)
	}
	if err := pol.Do(ctx, req, fn); err != nil {
		return false, err
	}
	if dryRun {
		// A denial is an error, so the decision is to allow or to hold.
		outcome := "allowed"
		if decision, _ := pol.Check(req); decision == policy.Confirm {
			outcome = "held for approval"
		}
		if _, err := fmt.Fprintf(out, "Dry run: %s would be %s. Nothing was done.\n", req.Action, outcome); err != nil {
			return false, fmt.Errorf("write result: %w", err)
		}
		return false, nil
	}
	return true, nil
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
