// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	defaultPort     = "7443"
	defaultHTTPPort = "7080"
	dbFile          = "hearth.db"
	// metricsDBFile holds the hub's own host metrics; not replicated.
	metricsDBFile = "metrics.db"
	// auditSpoolDir holds the audit entries the hub could not write yet;
	// not replicated.
	auditSpoolDir = "audit-spool"
)

// defaultDataDir is HEARTH_DATA_DIR if set, %ProgramData%\Hearth\<role> on
// Windows, /var/lib/hearth/<role> for root, and the user's XDG data dir
// otherwise.
func defaultDataDir(role string) string {
	if v := os.Getenv("HEARTH_DATA_DIR"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		return programDataDir(role)
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
// It is the stored policy document once the store holds documents, and the
// policy file until then, as the hub decides.
func cliPolicy(ctx context.Context, dataDir string, st *store.Store) (*policy.Engine, error) {
	cfg, stored, err := storedPolicy(ctx, st)
	if err != nil {
		return nil, err
	}
	if !stored {
		if cfg, err = loadPolicyConfig(dataDir); err != nil {
			return nil, err
		}
	}
	return policy.NewWithConfig(st.Audit(), st.Approvals(), cfg), nil
}

// storedPolicy reads the policy document, and reports whether the store
// holds configuration documents; when it holds some but no policy, the
// policy is the zero Config.
func storedPolicy(ctx context.Context, st *store.Store) (policy.Config, bool, error) {
	docs := st.ConfigDocs()
	if ok, err := docs.Available(ctx); err != nil || !ok {
		return policy.Config{}, false, err
	}
	all, err := docs.List(ctx, "")
	if err != nil || len(all) == 0 {
		return policy.Config{}, false, err
	}
	for _, d := range all {
		if d.Kind == store.ConfigPolicy {
			cfg, err := policy.ParseConfig(d.Content)
			if err != nil {
				return policy.Config{}, true, fmt.Errorf("the stored %s: %w", d.Name, err)
			}
			return cfg, true, nil
		}
	}
	return policy.Config{}, true, nil
}

// adminDo runs fn as the local operator through the hub's policy. An action
// the configuration holds waits here for approval. A dry run audits and
// prints the decision, runs nothing and returns false.
func adminDo(ctx context.Context, dataDir string, st *store.Store, out io.Writer, dryRun bool,
	req policy.Request, fn func(context.Context) error,
) (bool, error) {
	pol, err := cliPolicy(ctx, dataDir, st)
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
// data dir that holds no hub yet it opens the file directly. On a cluster
// member, reads still come from the local file but writes go through the
// running hub's control socket and so to the cluster: writing the local file
// directly would silently diverge from the other hubs.
func openHubStore(ctx context.Context, dataDir string) (*store.Store, error) {
	st, err := openHubStoreUnsealed(ctx, dataDir)
	if err != nil {
		return nil, err
	}
	if err := sealCLIAudit(st, dataDir); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
}

func openHubStoreUnsealed(ctx context.Context, dataDir string) (*store.Store, error) {
	path := filepath.Join(dataDir, dbFile)
	if !cluster.IsMember(dataDir) {
		return store.Open(ctx, path)
	}
	// Only a master writes what admin commands write (#382): on a
	// storage-only member nothing is written, not even an audit entry.
	if _, err := os.Stat(filepath.Join(dataDir, pki.CAKeyFile)); err != nil {
		return store.Open(ctx, path, store.WithoutUpgrade(),
			store.WithApplier(func(*store.Store) store.Applier { return storageOnly{} }))
	}
	cc, err := cluster.DialControl(dataDir)
	if err != nil {
		return nil, err
	}
	return store.Open(ctx, path, store.WithoutUpgrade(),
		store.WithApplier(func(*store.Store) store.Applier { return cc }))
}

// sealCLIAudit has the audit entries an admin command writes sealed (#387)
// when the data dir holds the hub CA key: otherwise a backup or a token made
// on a master's host would read as forged. The store's origin is new for
// each command, so its entries form a chain of their own and never take up
// the running hub's sequence numbers.
func sealCLIAudit(st *store.Store, dataDir string) error {
	if _, err := os.Stat(filepath.Join(dataDir, pki.CAKeyFile)); err != nil {
		return nil
	}
	ca, err := pki.LoadCA(dataDir, time.Now())
	if err != nil {
		return fmt.Errorf("load the hub CA to seal audit entries: %w", err)
	}
	ring, err := pki.NewAuditKeyring(ca)
	if err != nil {
		return err
	}
	st.SetAuditSealer(ring)
	return nil
}

// errStorageOnly refuses a write from an admin command on a storage-only
// member of a cluster.
var errStorageOnly = errors.New("this hub is a storage-only member of its cluster, and only a master makes changes: " +
	"run the command on a master's host, or use the web UI")

// storageOnly is the applier of a storage-only member's admin commands: it
// refuses every write.
type storageOnly struct{}

func (storageOnly) Apply(context.Context, store.Command) (store.Result, error) {
	return store.Result{}, errStorageOnly
}
