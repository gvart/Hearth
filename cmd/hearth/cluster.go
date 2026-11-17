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
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cluster", Short: "Manage the hub's Raft cluster"}
	cmd.AddCommand(newClusterTokenCmd(), newClusterStatusCmd())
	return cmd
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
