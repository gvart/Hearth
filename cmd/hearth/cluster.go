// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cluster", Short: "Manage the hub's Raft cluster"}
	cmd.AddCommand(newClusterTokenCmd(), newClusterStatusCmd(), newClusterRemoveCmd(), newClusterTransferCmd())
	return cmd
}

func newClusterRemoveCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "remove <node-id>",
		Short: "Remove a hub from the cluster and revoke its certificates",
		Long: "Remove a hub from the Raft configuration, so it no longer counts towards the majority, and revoke\n" +
			"its hub node certificates, so it can no longer talk to the cluster. Run it on any member's host while\n" +
			"its hub runs (a follower forwards it to the leader). The leader cannot be removed: run\n" +
			"`hearth cluster transfer-leadership` first. The node ID can join again later with a new join token.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterRemove(cmd.Context(), dataDir, args[0], cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func runClusterRemove(ctx context.Context, dataDir, nodeID string, out io.Writer) error {
	if err := cluster.ValidNodeID(nodeID); err != nil {
		return err
	}
	st, cc, err := openClusterControl(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	defer cc.Close()
	var revoked int
	err = policy.New(st.Audit()).Do(ctx, policy.Request{
		ActorKind: policy.ActorAdmin,
		ActorID:   adminActor(),
		Action:    policy.ClusterRemove,
		Target:    nodeID,
	}, func(ctx context.Context) error {
		revoked, err = cc.RemoveMember(ctx, nodeID)
		return err
	})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Removed hub %s from the cluster and revoked %d hub certificate(s).\n", nodeID, revoked); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func newClusterTransferCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "transfer-leadership [<node-id>]",
		Short: "Hand cluster leadership to another voter",
		Long: "Ask the leader to hand leadership to the given voter, or to the most up-to-date voter when none is\n" +
			"given, and wait until it has. Run it on any member's host while its hub runs.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			to := ""
			if len(args) == 1 {
				to = args[0]
			}
			return runClusterTransfer(cmd.Context(), dataDir, to, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func runClusterTransfer(ctx context.Context, dataDir, to string, out io.Writer) error {
	if to != "" {
		if err := cluster.ValidNodeID(to); err != nil {
			return err
		}
	}
	st, cc, err := openClusterControl(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	defer cc.Close()
	err = policy.New(st.Audit()).Do(ctx, policy.Request{
		ActorKind: policy.ActorAdmin,
		ActorID:   adminActor(),
		Action:    policy.ClusterTransferLeadership,
		Target:    to,
	}, func(ctx context.Context) error {
		return cc.TransferLeadership(ctx, to)
	})
	if err != nil {
		return err
	}
	msg := "Leadership transferred."
	if s, err := cc.Status(ctx); err == nil && s.LeaderID != "" {
		msg = "Leadership transferred; the leader is now " + s.LeaderID + "."
	}
	if _, err := fmt.Fprintln(out, msg); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// openClusterControl opens the store of a cluster member's hub (for the
// audit log) and a client of its control socket.
func openClusterControl(ctx context.Context, dataDir string) (*store.Store, *cluster.ControlClient, error) {
	if !cluster.IsMember(dataDir) {
		return nil, nil, fmt.Errorf("%s is not a cluster member: this hub runs standalone", dataDir)
	}
	st, err := openHubStore(ctx, dataDir)
	if err != nil {
		return nil, nil, err
	}
	cc, err := cluster.DialControl(dataDir)
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	return st, cc, nil
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
	return cmd
}

func runClusterTokenCreate(ctx context.Context, opts clusterTokenOptions, out io.Writer) error {
	if opts.ttl <= 0 {
		return errors.New("--ttl must be positive")
	}
	if !cluster.IsMember(opts.dataDir) {
		return fmt.Errorf("%s is not a cluster member: start its hub with --cluster to form a cluster first", opts.dataDir)
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
	err = policy.New(st.Audit()).Do(ctx, policy.Request{
		ActorKind: policy.ActorAdmin,
		ActorID:   adminActor(),
		Action:    policy.ClusterTokenCreate,
		Detail:    map[string]any{"ttl": opts.ttl.String()},
	}, func(ctx context.Context) error {
		return st.JoinTokens().Create(ctx, tok.Secret, expires)
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Cluster join token (single use, expires %s):\n  %s\n\n"+
		"On the new hub, with an empty data dir:\n  HEARTH_JOIN_TOKEN=%s hearth hub --join %s --advertise <new-hub-host>:%s\n",
		expires.Format(time.RFC3339), tok.EncodeJoin(), tok.EncodeJoin(), opts.hubURL, cluster.DefaultRaftPort)
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
		Long:  "Show the node ID, Raft state, leader, peers and log indexes as the hub on this host sees them.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClusterStatus(cmd.Context(), dataDir, asJSON, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func runClusterStatus(ctx context.Context, dataDir string, asJSON bool, out io.Writer) error {
	if !cluster.IsMember(dataDir) {
		return fmt.Errorf("%s is not a cluster member: this hub runs standalone", dataDir)
	}
	cc, err := cluster.DialControl(dataDir)
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
	leader := st.LeaderID
	if leader == "" {
		leader = "(none)"
	} else {
		leader += " at " + st.LeaderAddr
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "Node:\t%s\nState:\t%s\nLeader:\t%s\nTerm:\t%d\nLast index:\t%d\nCommit index:\t%d\nApplied index:\t%d\n\n",
		st.NodeID, st.State, leader, st.Term, st.LastIndex, st.CommitIndex, st.AppliedIndex)
	_, _ = fmt.Fprintln(tw, "PEER\tADDRESS\tSUFFRAGE\t")
	for _, p := range st.Peers {
		mark := ""
		if p.ID == st.LeaderID {
			mark = " (leader)"
		}
		_, _ = fmt.Fprintf(tw, "%s%s\t%s\t%s\t\n", p.ID, mark, p.Address, p.Suffrage)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	return nil
}
