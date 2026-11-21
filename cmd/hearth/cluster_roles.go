// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/hub"
)

func newClusterPromoteCmd() *cobra.Command {
	return newClusterRoleCmd(hub.ClusterOpPromote, "Give a member of an AP cluster the storage or master role",
		"Give a member of an AP cluster (--cluster-mode ap) the storage or master role. The member must allow it\n"+
			"(its --allow-roles). A member promoted to storage copies its rows from the others and shows\n"+
			"\"syncing\" until it has them all; one promoted to master fetches the CA key from this master and\n"+
			"starts serving the API and agents. Run it on a master's host while its hub runs. An agent host\n"+
			"cannot take a role: run `hearth hub --cluster-mode ap --join ...` on it instead.")
}

func newClusterDemoteCmd() *cobra.Command {
	return newClusterRoleCmd(hub.ClusterOpDemote, "Take the storage or master role from a member of an AP cluster",
		"Take the storage or master role from a member of an AP cluster (--cluster-mode ap). A storage member\n"+
			"hands its rows off first and keeps the role (\"draining\", with its progress in `hearth cluster\n"+
			"status`) until every row has its copies on the others. A demoted master spends its unused tokens,\n"+
			"expires its pending approvals, deletes the CA key and stops serving; its agents move to the other\n"+
			"masters. The last master and the last storage member cannot be demoted. Run it on a master's host.")
}

func newClusterRoleCmd(op, short, long string) *cobra.Command {
	var (
		dataDir string
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   op + " <member> <storage|master>",
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterRoleChange(cmd.Context(), dataDir, hub.ClusterChange{Op: op, Member: args[0], Role: args[1]},
				dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the action without doing it")
	return cmd
}

// runClusterRoleChange has the running hub of an AP master promote, demote
// or remove a member: decided by its policy engine and audited there.
func runClusterRoleChange(ctx context.Context, dataDir string, c hub.ClusterChange, dryRun bool, out io.Writer) error {
	if err := c.Check(); err != nil {
		return err
	}
	if !cluster.IsAP(dataDir) {
		return fmt.Errorf("%s is not a member of an ap cluster (--cluster-mode ap): roles change only there", dataDir)
	}
	cc, err := cluster.DialControl(dataDir)
	if err != nil {
		return err
	}
	defer cc.Close()
	req := cluster.RoleChangeRequest{Op: c.Op, Member: c.Member, Role: c.Role, DryRun: dryRun, Actor: adminActor()}
	if dryRun {
		var res apDryRun
		if err := cc.ChangeRoles(ctx, req, &res); err != nil {
			return err
		}
		return writeOut(out, "Dry run: cluster.%s of %s would be %s. Nothing was done.\n", c.Op, c.Member, decisionWord(res.Decision))
	}
	if c.Op == hub.ClusterOpRemove {
		var res cluster.Removal
		if err := cc.ChangeRoles(ctx, req, &res); err != nil {
			return err
		}
		return writeOut(out, "Removed %s from the cluster and revoked %d hub certificate(s); the others re-replicate its rows.\n",
			res.Member, res.Revoked)
	}
	var res cluster.RoleChange
	if err := cc.ChangeRoles(ctx, req, &res); err != nil {
		return err
	}
	switch res.State {
	case cluster.RoleSyncing:
		return writeOut(out, "Promoted %s to storage: it is copying its rows (syncing); see `hearth cluster status`.\n", res.Member)
	case cluster.RoleDraining:
		return writeOut(out, "Demoting %s from storage: it is handing its rows off (draining) and keeps the role until "+
			"every row has its copies; see `hearth cluster status`.\n", res.Member)
	case cluster.RoleDone:
		if c.Op == hub.ClusterOpPromote {
			return writeOut(out, "Promoted %s to %s.\n", res.Member, res.Role)
		}
		return writeOut(out, "Demoted %s from %s.\n", res.Member, res.Role)
	}
	return writeOut(out, "%s %s: %s.\n", c.Op, res.Member, res.State)
}

func decisionWord(d string) string {
	if d == "confirm" {
		return "held for approval"
	}
	return "allowed"
}

func writeOut(out io.Writer, format string, args ...any) error {
	if _, err := fmt.Fprintf(out, format, args...); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}
