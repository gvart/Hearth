// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newApprovalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approval",
		Short: "List, approve and deny actions held for approval",
		Long: "Actions the policy configuration (<data-dir>/policy.yaml) marks \"confirm\" are held until an\n" +
			"operator approves or denies them, or they expire and are denied. Run these on a hub host.",
	}
	cmd.AddCommand(newApprovalListCmd(), newApprovalDecideCmd(true), newApprovalDecideCmd(false))
	return cmd
}

func newApprovalListCmd() *cobra.Command {
	var (
		dataDir string
		all     bool
		limit   int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pending approvals, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runApprovalList(cmd.Context(), dataDir, all, limit, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&all, "all", false, "list decided and expired approvals too")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of approvals to list")
	return cmd
}

func runApprovalList(ctx context.Context, dataDir string, all bool, limit int, out io.Writer) error {
	st, err := openExistingHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	status := store.ApprovalPending
	if all {
		status = ""
	}
	aps, err := st.Approvals().List(ctx, status, limit)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tREQUESTED\tEXPIRES\tACTOR\tACTION\tCLASS\tTARGET\tSTATUS")
	for _, a := range aps {
		status := a.Status
		if a.DecidedBy != "" {
			status += " by " + a.DecidedBy
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s/%s\t%s\t%s\t%s\t%s\n", a.ID, a.CreatedAt.Local().Format(time.DateTime),
			a.ExpiresAt.Local().Format(time.TimeOnly), a.ActorKind, a.ActorID, a.Action, a.Class, a.Target, status)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write approvals: %w", err)
	}
	return nil
}

func newApprovalDecideCmd(approve bool) *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "deny <id>",
		Short: "Deny an action held for approval",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApprovalDecide(cmd.Context(), dataDir, args[0], false, "", cmd.OutOrStdout())
		},
	}
	if approve {
		cmd.Use, cmd.Short = "approve <id>", "Approve an action held for approval: it runs at once"
		cmd.Long = "Approve an action held for approval: it runs at once. Approving takes the admin password\n" +
			"again, prompted without echo on a terminal, or else the first line of stdin."
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			lines := &lineReader{in: cmd.InOrStdin(), buf: bufio.NewReader(cmd.InOrStdin()), prompt: cmd.ErrOrStderr()}
			pw, err := lines.read("Admin password: ")
			if err != nil {
				return err
			}
			return runApprovalDecide(cmd.Context(), dataDir, args[0], true, pw, cmd.OutOrStdout())
		}
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

// runApprovalDecide approves, with the admin password, or denies approval id.
func runApprovalDecide(ctx context.Context, dataDir, id string, approve bool, password string, out io.Writer) error {
	st, err := openExistingHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	pol, err := cliPolicy(dataDir, st)
	if err != nil {
		return err
	}
	reauth := func(ctx context.Context) error { return hub.CheckAdminPassword(ctx, st, password) }
	err = pol.Decide(ctx, policy.ActorAdmin, adminActor(), id, approve, reauth)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no approval %s", id)
	}
	if err != nil {
		return err
	}
	verb := "Denied"
	if approve {
		verb = "Approved"
	}
	if _, err := fmt.Fprintf(out, "%s %s.\n", verb, id); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// openExistingHubStore is openHubStore that fails on a wrong data dir
// instead of creating an empty database there.
func openExistingHubStore(ctx context.Context, dataDir string) (*store.Store, error) {
	if _, err := os.Stat(filepath.Join(dataDir, dbFile)); err != nil {
		return nil, fmt.Errorf("open hub database: %w (has `hearth hub` been started with --data-dir %s?)", err, dataDir)
	}
	return openHubStore(ctx, dataDir)
}
