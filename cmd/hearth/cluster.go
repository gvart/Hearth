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
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cluster", Short: "Manage the hub's Raft cluster"}
	cmd.AddCommand(newClusterTokenCmd(), newClusterStatusCmd(), newClusterRemoveCmd(), newClusterTransferCmd(),
		newClusterMigrateCmd())
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
		Long: "Remove a hub from the Raft configuration, so it no longer counts towards the majority, and revoke\n" +
			"its hub node certificates, so it can no longer talk to the cluster. Run it on any member's host while\n" +
			"its hub runs (a follower forwards it to the leader). The leader cannot be removed: run\n" +
			"`hearth cluster transfer-leadership` first. The node ID can join again later with a new join token.",
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
	st, cc, err := openClusterControl(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	defer cc.Close()
	var revoked int
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.ClusterRemove,
		Target: nodeID,
	}, func(ctx context.Context) error {
		var err error
		revoked, err = cc.RemoveMember(ctx, nodeID)
		return err
	})
	if err != nil || !done {
		return err
	}
	if _, err := fmt.Fprintf(out, "Removed hub %s from the cluster and revoked %d hub certificate(s).\n", nodeID, revoked); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func newClusterTransferCmd() *cobra.Command {
	var (
		dataDir string
		dryRun  bool
	)
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
			return runClusterTransfer(cmd.Context(), dataDir, to, dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the action without doing it")
	return cmd
}

func runClusterTransfer(ctx context.Context, dataDir, to string, dryRun bool, out io.Writer) error {
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
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.ClusterTransferLeadership,
		Target: to,
	}, func(ctx context.Context) error {
		return cc.TransferLeadership(ctx, to)
	})
	if err != nil || !done {
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

func newClusterMigrateCmd() *cobra.Command {
	var (
		dataDir string
		to      int64
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate the cluster's database schema after a rolling upgrade",
		Long: "Migrate every hub's database to a newer schema through the Raft log, once every hub runs a hearth\n" +
			"that supports it (see the upgrade procedure in docs/cluster.md). Without --to it migrates to the\n" +
			"newest schema every hub supports. The leader refuses, naming the hubs, if any hub does not support\n" +
			"the target or cannot be asked. Downgrades are not supported: a migrated hub needs that hearth\n" +
			"version or a newer one from then on. Run it on any member's host while its hub runs.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClusterMigrate(cmd.Context(), dataDir, to, dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().Int64Var(&to, "to", 0, "schema version to migrate to (default: the newest every hub supports)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would be migrated and stop")
	return cmd
}

func runClusterMigrate(ctx context.Context, dataDir string, to int64, dryRun bool, out io.Writer) error {
	if to < 0 {
		return errors.New("--to must be positive")
	}
	st, cc, err := openClusterControl(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	defer cc.Close()
	status, err := cc.Status(ctx)
	if err != nil {
		return err
	}
	from, target, err := migratePlan(status, to)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HUB\tSCHEMA (DATABASE/SUPPORTED)\t")
	for _, p := range status.Peers {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t\n", p.ID, schemaColumn(p))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	switch {
	case target <= from && to == 0:
		_, err = fmt.Fprintf(out, "\nThe cluster is at schema %d, the newest every hub supports: nothing to migrate.\n", from)
		return err
	case target <= from:
		return fmt.Errorf("--to %d: the cluster is at schema %d already", to, from)
	case dryRun:
		_, err = fmt.Fprintf(out, "\nWould migrate the cluster from schema %d to %d (dry run).\n", from, target)
		if err != nil {
			return err
		}
	default:
		if _, err := fmt.Fprintf(out, "\nMigrating the cluster from schema %d to %d...\n", from, target); err != nil {
			return fmt.Errorf("write plan: %w", err)
		}
	}
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.ClusterMigrate,
		Target: fmt.Sprintf("schema %d", target),
		Detail: map[string]any{"from": from, "to": target},
	}, func(ctx context.Context) error {
		_, err := cc.MigrateSchema(ctx, target)
		return err
	})
	if err != nil || !done {
		return err
	}
	if _, err := fmt.Fprintf(out, "Migrated: the cluster is at schema %d.\n", target); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// migratePlan returns the cluster's schema, from this hub's database, and
// the schema to migrate to: to, or when to is zero the newest schema every
// hub supports, which needs every hub's schema.
func migratePlan(st cluster.Status, to int64) (from, target int64, err error) {
	var (
		found   bool
		unknown []string
	)
	target = to
	for _, p := range st.Peers {
		if p.Schema == nil {
			unknown = append(unknown, fmt.Sprintf("%s (%s)", p.ID, p.SchemaError))
			continue
		}
		if p.ID == st.NodeID {
			from, found = p.Schema.Current, true
		}
		if to == 0 && (target == 0 || p.Schema.Max < target) {
			target = p.Schema.Max
		}
	}
	switch {
	case !found:
		return 0, 0, errors.New("cannot read this hub's schema version")
	case to == 0 && len(unknown) > 0:
		return 0, 0, fmt.Errorf("cannot read the schema of every hub: %s; bring them back or remove them first, "+
			"or pass --to", strings.Join(unknown, ", "))
	}
	return from, target, nil
}

// schemaColumn is a peer's schema as "database/supported", or why it is unknown.
func schemaColumn(p cluster.Peer) string {
	if p.Schema == nil {
		return "? (" + p.SchemaError + ")"
	}
	return fmt.Sprintf("%d/%d", p.Schema.Current, p.Schema.Max)
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
		Long: "Show the node ID, Raft state, leader, peers and log indexes as the hub on this host sees them,\n" +
			"and each hub's database schema version and the newest its hearth supports.",
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
	_, _ = fmt.Fprintln(tw, "PEER\tADDRESS\tSUFFRAGE\tSCHEMA (DATABASE/SUPPORTED)\t")
	for _, p := range st.Peers {
		mark := ""
		if p.ID == st.LeaderID {
			mark = " (leader)"
		}
		_, _ = fmt.Fprintf(tw, "%s%s\t%s\t%s\t%s\t\n", p.ID, mark, p.Address, p.Suffrage, schemaColumn(p))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	return nil
}
