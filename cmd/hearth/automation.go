// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/automation"
)

func newAutomationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "automation",
		Short: "Check automations and their run history",
		Long: "Automations are YAML files in the hub's automations dir (--automations-dir of `hearth hub`,\n" +
			"default <data-dir>/automations). The hub reloads them when they change and runs them on the\n" +
			"cluster leader only.",
	}
	cmd.AddCommand(newAutomationPlanCmd(), newAutomationRunsCmd())
	return cmd
}

func newAutomationPlanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "plan <file>",
		Short: "Validate an automation file and print what it would do, without running anything",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kinds := automation.Builtin(slog.New(slog.DiscardHandler))
			maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
			maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{}))
			a, err := automation.LoadFile(args[0], kinds)
			if err != nil {
				return err
			}
			return automation.Plan(cmd.OutOrStdout(), a)
		},
	}
}

func newAutomationRunsCmd() *cobra.Command {
	var (
		dataDir string
		limit   int
	)
	cmd := &cobra.Command{
		Use:   "runs [automation-id]",
		Short: "List recent automation runs, newest first",
		Long:  "List recent runs of one automation, or of all of them. Run it on a hub host.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) == 1 {
				id = args[0]
			}
			return runAutomationRuns(cmd.Context(), dataDir, id, limit, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of runs to list")
	return cmd
}

func runAutomationRuns(ctx context.Context, dataDir, id string, limit int, out io.Writer) error {
	// Fail on a wrong data dir instead of creating an empty database there.
	if _, err := os.Stat(filepath.Join(dataDir, dbFile)); err != nil {
		return fmt.Errorf("open hub database: %w (has `hearth hub` been started with --data-dir %s?)", err, dataDir)
	}
	st, err := openHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	runs, err := st.AutomationRuns().List(ctx, id, limit)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STARTED\tAUTOMATION\tTRIGGER\tSTATUS\tDURATION\tERROR")
	for _, r := range runs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.StartedAt.Local().Format(time.DateTime), r.AutomationID,
			r.TriggerID, r.Status, r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond), r.Error)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write runs: %w", err)
	}
	return nil
}
