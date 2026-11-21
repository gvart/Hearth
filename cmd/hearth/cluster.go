// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cluster", Short: "Manage the hub's cluster"}
	cmd.AddCommand(newClusterTokenCmd(), newClusterStatusCmd(), newClusterRemoveCmd(), newClusterCACmd(),
		newClusterPromoteCmd(), newClusterDemoteCmd())
	return cmd
}

func newClusterRemoveCmd() *cobra.Command {
	var (
		dataDir string
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   "remove <node-id>",
		Short: "Remove a hub from the cluster and revoke its certificates",
		Long: "Remove a hub from the cluster: its hub node certificates are revoked, every member forgets it and\n" +
			"the others re-replicate its rows. Run it on a master's host while its hub runs. A hub does not remove\n" +
			"itself, nor the last master or storage member. The node ID can join again later with a new join token.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterRemove(cmd.Context(), dataDir, args[0], dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the action without doing it")
	return cmd
}

func runClusterRemove(ctx context.Context, dataDir, nodeID string, dryRun bool, out io.Writer) error {
	if err := cluster.ValidNodeID(nodeID); err != nil {
		return err
	}
	return runClusterRoleChange(ctx, dataDir, hub.ClusterChange{Op: hub.ClusterOpRemove, Member: nodeID}, dryRun, out)
}

// dialHub returns a client of the control socket of the hub on dataDir.
func dialHub(dataDir string) (*cluster.ControlClient, error) {
	if !cluster.IsMember(dataDir) {
		return nil, fmt.Errorf("%s holds no hub: start `hearth hub` with it first", dataDir)
	}
	return cluster.DialControl(dataDir)
}

func newClusterTokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage cluster join tokens"}
	cmd.AddCommand(newClusterTokenCreateCmd())
	return cmd
}

type clusterTokenOptions struct {
	dataDir string
	ttl     time.Duration
	hubURL  string
	dryRun  bool
}

func newClusterTokenCreateCmd() *cobra.Command {
	opts := clusterTokenOptions{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a single-use token that lets another hub join this cluster",
		Long: "Create a single-use cluster join token and print the command that joins a new hub.\n" +
			"Run it on any member's host while its hub runs (a follower forwards it to the leader). A joined\n" +
			"hub receives the hub CA, private key included: treat the token like the CA key itself.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClusterTokenCreate(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().DurationVar(&opts.ttl, "ttl", 15*time.Minute, "how long the token stays valid")
	cmd.Flags().StringVar(&opts.hubURL, "hub-url", "https://"+hostnameOr("localhost")+":"+defaultPort,
		"this hub's URL to put in the join command")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "decide and audit the action without creating a token")
	return cmd
}

func runClusterTokenCreate(ctx context.Context, opts clusterTokenOptions, out io.Writer) error {
	if opts.ttl <= 0 {
		return errors.New("--ttl must be positive")
	}
	if !cluster.IsMember(opts.dataDir) {
		return fmt.Errorf("%s holds no hub: start `hearth hub` with it first", opts.dataDir)
	}
	caCert, err := pki.LoadCACert(opts.dataDir)
	if err != nil {
		return err
	}
	st, err := openHubStore(ctx, opts.dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	tok, err := pki.NewToken(caCert)
	if err != nil {
		return err
	}
	expires := time.Now().Add(opts.ttl)
	done, err := adminDo(ctx, opts.dataDir, st, out, opts.dryRun, policy.Request{
		Action: policy.ClusterTokenCreate,
		Detail: map[string]any{"ttl": opts.ttl.String()},
	}, func(ctx context.Context) error {
		return st.JoinTokens().Create(ctx, tok.Secret, expires)
	})
	if err != nil || !done {
		return err
	}
	_, err = fmt.Fprintf(out, "Cluster join token (single use, expires %s):\n  %s\n\n"+
		"On the new hub, with an empty data dir:\n  HEARTH_JOIN_TOKEN=%s hearth hub --join %s "+
		"--cluster-advertise <new-hub-host>:%s\n",
		expires.Format(time.RFC3339), tok.EncodeJoin(), tok.EncodeJoin(), opts.hubURL, cluster.DefaultPort)
	if err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	return nil
}

func newClusterStatusCmd() *cobra.Command {
	var (
		dataDir string
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show this hub's view of the cluster",
		Long: "Show the cluster as the hub on this host sees it: its node ID, the storage members, N and whether\n" +
			"the cluster is highly available, and every member with its roles, allowed roles, state (alive,\n" +
			"suspect, dead, left) and database schema.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClusterStatus(cmd.Context(), dataDir, asJSON, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func runClusterStatus(ctx context.Context, dataDir string, asJSON bool, out io.Writer) error {
	cc, err := dialHub(dataDir)
	if err != nil {
		return err
	}
	defer cc.Close()
	st, err := cc.Status(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	return writeStatus(out, st)
}

// writeMembers writes the gossip members table; nothing when the hub does
// not gossip.
func writeMembers(tw io.Writer, members []cluster.MemberInfo) {
	if len(members) == 0 {
		return
	}
	_, _ = fmt.Fprintln(tw, "\nMEMBER\tADDRESS\tROLES\tALLOWED ROLES\tSTATE\tSCHEMA\t")
	for _, m := range members {
		state := m.State
		switch {
		case m.Syncing:
			state += ", syncing"
		case m.Draining:
			state += fmt.Sprintf(", draining %d%%", m.Progress)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t\n", m.ID, m.Address, m.Roles, m.AllowedRoles, state, m.Schema)
	}
}

// writeStatus writes the status of a cluster member.
func writeStatus(out io.Writer, st cluster.Status) error {
	ha := "yes"
	if !st.HighlyAvailable {
		ha = "no: not highly available (fewer than 2 storage members, or N < 2)"
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "Node:\t%s\nStorage members:\t%d\nReplicas (N):\t%d\nHighly available:\t%s\n",
		st.NodeID, st.StorageMembers, st.Replicas, ha)
	writeMembers(tw, st.Members)
	if groups := cluster.HostFlagGroups(st.Members); len(groups) > 1 {
		parts := make([]string, len(groups))
		for i, g := range groups {
			parts[i] = strings.Join(g, ", ")
		}
		_, _ = fmt.Fprintf(tw, "\nHost flags differ (--allow-dangerous-automation):\t%s\n", strings.Join(parts, " | "))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	return nil
}
