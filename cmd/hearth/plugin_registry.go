// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// The plugin registry (#75), the CLI's side: the hub's flags that name the
// signed index and the keys it trusts, `hearth plugin search|install|
// update|remove` on a hub host, and `hearth plugin index` for whoever
// publishes an index.

// registrySyncEvery is how often a hub picks up plugins installed, updated
// or removed by `hearth plugin` in another process.
const registrySyncEvery = 2 * time.Second

// signingKeyEnv holds an index signing key, the base64 of an Ed25519 seed,
// for `hearth plugin index sign`.
const signingKeyEnv = "HEARTH_PLUGIN_INDEX_SIGNING_KEY"

// registryOptions name a plugin index and the keys it must be signed with.
type registryOptions struct {
	index string
	keys  []string
}

func addRegistryFlags(cmd *cobra.Command, o *registryOptions) {
	cmd.Flags().StringVar(&o.index, "plugin-index", os.Getenv("HEARTH_PLUGIN_INDEX"),
		"signed plugin index to install WASM plugins from: an http(s) URL or a file path (env HEARTH_PLUGIN_INDEX; "+
			"default: none, the registry is off; see docs/plugins.md)")
	cmd.Flags().StringArrayVar(&o.keys, "plugin-index-key", splitList(os.Getenv("HEARTH_PLUGIN_INDEX_KEYS")),
		"base64 Ed25519 public key a plugin index must be signed with; repeatable "+
			"(env HEARTH_PLUGIN_INDEX_KEYS, comma-separated; default: none)")
}

// registry is the configured index; nil when none is.
func (o registryOptions) registry() (*plugins.Registry, error) {
	return plugins.NewRegistry(o.index, o.keys)
}

// newRegistrySync runs the plugins installed in dataDir on mgr.
func newRegistrySync(dataDir string, mgr *plugins.Manager, log *slog.Logger) *plugins.RegistrySync {
	return &plugins.RegistrySync{Store: plugins.NewInstalledStore(dataDir), Manager: mgr, Log: log.With("component", "plugins")}
}

// fetchIndex reads and verifies the configured index.
func (o registryOptions) fetchIndex(ctx context.Context) (*plugins.Registry, *plugins.Index, error) {
	reg, err := o.registry()
	if err != nil {
		return nil, nil, err
	}
	if reg == nil {
		return nil, nil, fmt.Errorf("%w: pass --plugin-index and --plugin-index-key, or set HEARTH_PLUGIN_INDEX and HEARTH_PLUGIN_INDEX_KEYS as the hub has them",
			plugins.ErrRegistryOff)
	}
	idx, err := reg.Fetch(ctx)
	return reg, idx, err
}

func newPluginSearchCmd() *cobra.Command {
	var reg registryOptions
	cmd := &cobra.Command{
		Use:   "search [text]",
		Short: "List the plugins the signed plugin index offers",
		Long:  "List the newest version of each plugin the index offers whose name or description holds text, if given.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, idx, err := reg.fetchIndex(cmd.Context())
			if err != nil {
				return err
			}
			q := ""
			if len(args) == 1 {
				q = strings.ToLower(args[0])
			}
			out := cmd.OutOrStdout()
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "PLUGIN\tVERSION\tHTTP ACCESS\tDESCRIPTION")
			n := 0
			for _, e := range idx.Newest() {
				if q != "" && !strings.Contains(strings.ToLower(e.Name+" "+e.Description), q) {
					continue
				}
				n++
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Name, e.Version, hostAccess(e.Host), e.Description)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if n == 0 {
				_, err = fmt.Fprintln(out, "No plugin matches.")
			}
			return err
		},
	}
	addRegistryFlags(cmd, &reg)
	return cmd
}

// hostAccess says what an entry may reach outside its sandbox.
func hostAccess(g plugins.HostGrants) string {
	if hosts := plugins.HTTPAllow(g); len(hosts) > 0 {
		return strings.Join(hosts, ",")
	}
	return "none"
}

// describeEntry prints what installing e grants.
func describeEntry(out io.Writer, e plugins.IndexEntry) {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			_, _ = fmt.Fprintf(w, "  %s\t%s\n", k, v)
		}
	}
	row("Plugin", e.Name+" "+e.Version)
	row("Description", e.Description)
	row("Author", e.Author)
	row("License", e.License)
	row("Homepage", e.Homepage)
	row("Module", "wasm, sha256 "+e.SHA256)
	row("Memory", fmt.Sprintf("%d MiB at most", e.MemoryMiB()))
	row("HTTP access", hostAccess(e.Host))
	row("Capabilities", strings.Join(e.Capabilities, ", "))
	row("Commands", strings.Join(plugins.CommandList(e.Commands), ", "))
	_ = w.Flush()
}

// confirm asks a yes or no question on in; anything but y or yes is no.
func confirm(in io.Reader, out io.Writer, question string) (bool, error) {
	if _, err := fmt.Fprintf(out, "%s [y/N] ", question); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

// registryChangeFlags are those of install and update.
type registryChangeFlags struct {
	dataDir, version string
	yes, dryRun      bool
	allowDowngrade   bool
	reg              registryOptions
}

func newPluginInstallCmd() *cobra.Command {
	var f registryChangeFlags
	cmd := &cobra.Command{
		Use:   "install <name>",
		Short: "Install a WASM plugin from the signed plugin index on this hub",
		Long: "Install a plugin the index offers: the hub checks the index's signature, downloads the module and checks\n" +
			"its SHA-256, shows what it may do (its commands and the hosts it may reach) and asks before it installs.\n" +
			"The install is the dangerous policy action plugin.registry.install, audited. The running hub starts it\n" +
			"within seconds. Run it on a hub host, as the hub's user.",
		Example: "  hearth plugin install go-wasm-lamp --plugin-index https://plugins.example.com/index.json --plugin-index-key <key>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryChange(cmd, f, policy.PluginRegistryInstall, args[0])
		},
	}
	addChangeFlags(cmd, &f)
	return cmd
}

func newPluginUpdateCmd() *cobra.Command {
	var f registryChangeFlags
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update a plugin installed from the plugin index",
		Long: "Update an installed plugin to the newest version the index offers, or to --version. Never automatic:\n" +
			"`hearth plugin list` says when an update is available. An older version is refused unless\n" +
			"--allow-downgrade. The update is the dangerous policy action plugin.registry.update, audited.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryChange(cmd, f, policy.PluginRegistryUpdate, args[0])
		},
	}
	addChangeFlags(cmd, &f)
	cmd.Flags().BoolVar(&f.allowDowngrade, "allow-downgrade", false, "allow an older version than the one installed")
	return cmd
}

func addChangeFlags(cmd *cobra.Command, f *registryChangeFlags) {
	cmd.Flags().StringVar(&f.dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&f.version, "version", "", "the version to install (default: the newest)")
	cmd.Flags().BoolVarP(&f.yes, "yes", "y", false, "do not ask before installing")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "decide and audit the change without making it")
	addRegistryFlags(cmd, &f.reg)
}

func runRegistryChange(cmd *cobra.Command, f registryChangeFlags, action policy.Action, name string) error {
	ctx, out := cmd.Context(), cmd.OutOrStdout()
	if err := plugins.CheckInstaller(f.dataDir); err != nil {
		return err
	}
	reg, idx, err := f.reg.fetchIndex(ctx)
	if err != nil {
		return err
	}
	st := plugins.NewInstalledStore(f.dataDir)
	var c plugins.Change
	if action == policy.PluginRegistryInstall {
		c, err = plugins.PlanInstall(idx, reg.Source, st, name, f.version)
	} else {
		c, err = plugins.PlanUpdate(idx, reg.Source, st, name, f.version, f.allowDowngrade)
	}
	if err != nil {
		return err
	}
	module, err := reg.Download(ctx, c.Entry)
	if err != nil {
		return err
	}
	verb := "Install"
	if c.Previous != nil {
		verb = "Update " + c.Previous.Entry.Version + " to"
	}
	if _, err := fmt.Fprintf(out, "%s %s %s, from %s:\n", verb, c.Entry.Name, c.Entry.Version, c.Source); err != nil {
		return err
	}
	describeEntry(out, c.Entry)
	if !f.yes && !f.dryRun {
		ok, err := confirm(cmd.InOrStdin(), out, "It runs in the hub's WASM sandbox with only the access above. "+strings.SplitN(verb, " ", 2)[0]+" it?")
		if err != nil {
			return err
		}
		if !ok {
			_, err := fmt.Fprintln(out, "Nothing was changed.")
			return err
		}
	}
	st0, err := openExistingHubStore(ctx, f.dataDir)
	if err != nil {
		return err
	}
	defer st0.Close()
	done, err := adminDo(ctx, f.dataDir, st0, out, f.dryRun, c.Request(), func(context.Context) error {
		return st.Put(c.Entry, module, c.Source, policy.ActorAdmin+"/"+adminActor(), time.Now())
	})
	if err != nil || !done {
		return err
	}
	_, err = fmt.Fprintf(out, "Installed %s %s. The running hub starts it within seconds; `hearth plugin list` shows it.\n", c.Entry.Name, c.Entry.Version)
	return err
}

func newPluginRemoveCmd() *cobra.Command {
	var (
		dataDir string
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Uninstall a plugin installed from the plugin index",
		Long:  "Uninstall a plugin installed from a registry: the running hub stops it within seconds. The safe policy action plugin.registry.remove, audited.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, out := cmd.Context(), cmd.OutOrStdout()
			if err := plugins.CheckInstaller(dataDir); err != nil {
				return err
			}
			st := plugins.NewInstalledStore(dataDir)
			in, ok, err := st.Get(args[0])
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("plugin %s: %w (see `hearth plugin list`)", args[0], plugins.ErrNotInstalled)
			}
			db, err := openExistingHubStore(ctx, dataDir)
			if err != nil {
				return err
			}
			defer db.Close()
			done, err := adminDo(ctx, dataDir, db, out, dryRun, plugins.RemoveRequest(in), func(context.Context) error {
				return st.Remove(in.Entry.Name)
			})
			if err != nil || !done {
				return err
			}
			_, err = fmt.Fprintf(out, "Removed %s %s.\n", in.Entry.Name, in.Entry.Version)
			return err
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the removal without removing")
	return cmd
}

// listInstalled prints the plugins installed from a registry, and the
// updates the index offers if one is configured.
func listInstalled(ctx context.Context, out io.Writer, dataDir string, reg registryOptions) error {
	list, err := plugins.NewInstalledStore(dataDir).List()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return nil
	}
	updates := map[string]string{}
	note := ""
	if r, err := reg.registry(); err == nil && r != nil {
		if idx, err := r.Fetch(ctx); err == nil {
			for _, u := range plugins.Updates(idx, list) {
				updates[u.Name] = u.Available
			}
		} else {
			note = "Cannot check for updates: " + err.Error() + "\n"
		}
	}
	if _, err := fmt.Fprintln(out, "\nInstalled from a plugin index (run on this hub):"); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PLUGIN\tVERSION\tUPDATE\tSHA256\tHTTP ACCESS\tINSTALLED")
	for _, in := range list {
		u := updates[in.Entry.Name]
		if u == "" {
			u = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s by %s\n", in.Entry.Name, in.Entry.Version, u, in.Entry.SHA256[:12],
			hostAccess(in.Entry.Host), in.InstalledAt.Local().Format(time.DateTime), in.InstalledBy)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err = io.WriteString(out, note)
	return err
}

func newPluginIndexCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "index",
		Short: "Make and sign a plugin index, for whoever publishes one",
		Long: "A plugin index is a JSON file (see docs/plugins.md) served with its signature, <index>.sig. keygen makes\n" +
			"a signing key, sign signs an index with it, verify checks a signature with a public key.",
	}
	cmd.AddCommand(newIndexKeygenCmd(), newIndexSignCmd(), newIndexVerifyCmd())
	return cmd
}

func newIndexKeygenCmd() *cobra.Command {
	var keyFile string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Make an index signing key",
		Long: "Write a new Ed25519 signing key to --key-file (0600; it must not exist) and print its public key, which\n" +
			"hubs pass with --plugin-index-key. Keep the key file offline; it is never printed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			f, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fmt.Errorf("key file: %w", err)
			}
			if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Wrote the signing key to %s.\nPublic key (--plugin-index-key): %s\n",
				keyFile, base64.StdEncoding.EncodeToString(pub))
			return err
		},
	}
	cmd.Flags().StringVar(&keyFile, "key-file", "", "where to write the signing key (required)")
	_ = cmd.MarkFlagRequired("key-file")
	return cmd
}

func newIndexSignCmd() *cobra.Command {
	var keyFile string
	cmd := &cobra.Command{
		Use:   "sign <index.json>",
		Short: "Sign a plugin index",
		Long: "Check the index, then write its signature to <index.json>.sig, with the key in --key-file or, without\n" +
			"it, in " + signingKeyEnv + " (the base64 of an Ed25519 seed). Publish both files side by side.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			seed := os.Getenv(signingKeyEnv)
			if keyFile != "" {
				b, err := os.ReadFile(keyFile)
				if err != nil {
					return fmt.Errorf("key file: %w", err)
				}
				seed = string(b)
			}
			if strings.TrimSpace(seed) == "" {
				return fmt.Errorf("no signing key: pass --key-file or set %s", signingKeyEnv)
			}
			key, err := plugins.ParseIndexSeed(seed)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			idx, err := plugins.ParseIndex(b)
			if err != nil {
				return err
			}
			if err := os.WriteFile(args[0]+plugins.IndexSigSuffix, plugins.SignIndex(key, b), 0o644); err != nil { //nolint:gosec // a signature is published
				return err
			}
			pub, _ := key.Public().(ed25519.PublicKey)
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Signed %s (%d plugin versions) with key %s: wrote %s%s.\n",
				args[0], len(idx.Plugins), base64.StdEncoding.EncodeToString(pub), args[0], plugins.IndexSigSuffix)
			return err
		},
	}
	cmd.Flags().StringVar(&keyFile, "key-file", "", "the signing key, as hearth plugin index keygen wrote it (default: env "+signingKeyEnv+")")
	return cmd
}

func newIndexVerifyCmd() *cobra.Command {
	var keys []string
	cmd := &cobra.Command{
		Use:   "verify <index.json>",
		Short: "Check a plugin index and its signature",
		Long:  "Check <index.json>.sig against the index and --key, then the index itself, as a hub would.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := plugins.NewRegistry(args[0], keys)
			if err != nil {
				return err
			}
			idx, err := r.Fetch(cmd.Context())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s verifies: %d plugin versions.\n", args[0], len(idx.Plugins))
			return err
		},
	}
	cmd.Flags().StringArrayVar(&keys, "key", nil, "base64 Ed25519 public key to check with; repeatable (required)")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}
