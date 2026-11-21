// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Import, export and delete the hub's configuration documents",
		Long: "policy.yaml, notify.yaml, the automation files and the runbook files are documents of the hub's\n" +
			"store, the same on every hub of a cluster, which every hub applies within seconds of a change.\n" +
			"Files on disk are import and export only. Run these commands on a hub host: they open the hub's\n" +
			"data dir directly. See docs/guardrails.md.",
	}
	cmd.AddCommand(newConfigImportCmd(), newConfigExportCmd(), newConfigDeleteCmd())
	return cmd
}

func newConfigImportCmd() *cobra.Command {
	var (
		dataDir, kind string
		dryRun        bool
	)
	cmd := &cobra.Command{
		Use:   "import <dir|file>",
		Short: "Validate configuration files and write them into the store, through policy (config.import)",
		Long: "Import a directory laid out like an export (policy.yaml, notify.yaml, automations/, runbooks/) or one\n" +
			"file. Each file adds or replaces the document of its name; documents not in the import stay.\n" +
			"The whole configuration the import would leave is validated first: nothing is written unless all\n" +
			"of it loads. notify.yaml is sealed before it is stored. The import is audited.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigImport(cmd.Context(), dataDir, args[0], kind, dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&kind, "kind", "", "kind of a single file: policy, notify, automation or runbook "+
		"(default: from its name, or its automations/ or runbooks/ directory)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate and audit the policy decision only; nothing is written")
	return cmd
}

func newConfigExportCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "export <dir>",
		Short: "Write the configuration documents to files, through policy (config.export)",
		Long: "Write every document into dir, in the layout import reads, each file readable by its owner only.\n" +
			"notify.yaml is written in clear: it holds the notification credentials. Only this command, on a hub\n" +
			"host, exports it; no API returns it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigExport(cmd.Context(), dataDir, args[0], cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func newConfigDeleteCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "delete <automation|runbook> <name>",
		Short: "Delete an automation or runbook document, through policy (config.import)",
		Long: "Delete the document name (its file name, such as backup.yaml): every hub stops running it.\n" +
			"policy.yaml and notify.yaml are not deleted: import an empty file instead.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigDelete(cmd.Context(), dataDir, args[0], args[1], cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

// openConfigStore opens the hub's store for a config command, which needs
// documents (schema 28) and the hub to have imported its own files first.
func openConfigStore(ctx context.Context, dataDir string) (*store.Store, error) {
	st, err := openExistingHubStore(ctx, dataDir)
	if err != nil {
		return nil, err
	}
	docs := st.ConfigDocs()
	ok, err := docs.Available(ctx)
	if err == nil && !ok {
		err = fmt.Errorf("the database is at an older schema without configuration documents: upgrade every hub of the cluster, " +
			"then try again")
	}
	if err == nil {
		var all []store.ConfigDoc
		if all, err = docs.List(ctx, ""); err == nil && len(all) == 0 {
			err = errors.New("the store holds no configuration yet: start `hearth hub` once, so it imports its own files first")
		}
	}
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
}

// cliNotifySealer is the hub's notify sealer, from the CA key in dataDir.
func cliNotifySealer(dataDir string) (*kubernetes.Sealer, error) {
	if _, err := os.Stat(filepath.Join(dataDir, pki.CAKeyFile)); err != nil {
		return nil, fmt.Errorf("read the hub CA key: %w", err)
	}
	ca, err := pki.LoadOrCreateCA(dataDir, time.Now())
	if err != nil {
		return nil, err
	}
	keys, err := ca.KeyDERs()
	if err != nil {
		return nil, err
	}
	s, err := kubernetes.NewPurposeSealer(keys[0], notifySealInfo)
	if err != nil {
		return nil, err
	}
	// During a CA rotation the stored document may be sealed with either key.
	if err := s.SetSecrets(keys...); err != nil {
		return nil, err
	}
	return s, nil
}

// cliKinds are the step types an import validates automations and runbooks
// with: those `hearth automation plan` knows, notify actions checked against
// the imported channels.
func cliKinds(n *notify.Notifier) automation.Kinds {
	kinds := automation.Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{Notifier: n}))
	kinds.Actions["script"] = automation.Script(automation.ScriptDeps{})
	return kinds
}

func runConfigImport(ctx context.Context, dataDir, path, kind string, dryRun bool, out io.Writer) error {
	incoming, err := hubconfig.ReadPath(path, kind)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(incoming) == 0 {
		return fmt.Errorf("%s holds no configuration files", path)
	}
	st, err := openConfigStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	sealer, err := cliNotifySealer(dataDir)
	if err != nil {
		return err
	}
	current, err := hubconfig.Load(ctx, st.ConfigDocs(), sealer)
	if err != nil {
		return err
	}
	if err := hubconfig.CheckLockout(incoming); err != nil {
		return fmt.Errorf("nothing imported: %w", err)
	}
	if err := hubconfig.Validate(hubconfig.Overlay(current, incoming), cliKinds); err != nil {
		return fmt.Errorf("nothing imported: %w", err)
	}
	sealed, err := hubconfig.Seal(incoming, sealer)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(incoming))
	for _, d := range incoming {
		ids = append(ids, d.ID())
	}
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.ConfigImport, Detail: map[string]any{"documents": ids},
	}, func(ctx context.Context) error {
		return st.ConfigDocs().Put(ctx, policy.ActorAdmin+"/"+adminActor(), sealed, time.Now())
	})
	if err != nil || !done {
		return err
	}
	_, err = fmt.Fprintf(out, "Imported %d documents: every hub applies them within seconds.\n", len(ids))
	for _, id := range ids {
		if err == nil {
			_, err = fmt.Fprintf(out, "  %s\n", id)
		}
	}
	return err
}

func runConfigExport(ctx context.Context, dataDir, dir string, out io.Writer) error {
	st, err := openConfigStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	sealer, err := cliNotifySealer(dataDir)
	if err != nil {
		return err
	}
	var docs []hubconfig.Doc
	if _, err := adminDo(ctx, dataDir, st, out, false, policy.Request{Action: policy.ConfigExport}, func(ctx context.Context) error {
		if docs, err = hubconfig.Load(ctx, st.ConfigDocs(), sealer); err != nil {
			return err
		}
		return hubconfig.WriteDir(dir, docs)
	}); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Exported %d documents to %s.\n", len(docs), dir)
	return err
}

func runConfigDelete(ctx context.Context, dataDir, kind, name string, out io.Writer) error {
	if kind != store.ConfigAutomation && kind != store.ConfigRunbook {
		return fmt.Errorf("only automation and runbook documents are deleted, not %q: import an empty file instead", kind)
	}
	st, err := openConfigStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	id := store.ConfigDocID(kind, name)
	if _, err := st.ConfigDocs().Get(ctx, kind, name); err != nil {
		return err
	}
	if _, err := adminDo(ctx, dataDir, st, out, false, policy.Request{
		Action: policy.ConfigImport, Target: id, Detail: map[string]any{"delete": id},
	}, func(ctx context.Context) error { return st.ConfigDocs().Delete(ctx, kind, name) }); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Deleted %s: every hub stops using it within seconds.\n", id)
	return err
}
