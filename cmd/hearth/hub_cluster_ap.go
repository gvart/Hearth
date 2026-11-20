// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// Cluster modes (--cluster-mode).
const (
	clusterModeRaft = "raft"
	clusterModeAP   = "ap"
)

func addAPClusterFlags(cmd *cobra.Command, o *clusterOptions) {
	mode := os.Getenv("HEARTH_CLUSTER_MODE")
	if mode == "" {
		mode = clusterModeRaft
	}
	cmd.Flags().StringVar(&o.mode, "cluster-mode", mode,
		"cluster mode: raft (a leader replicates every write) or ap (leaderless and sharded, "+
			"docs/design/ap-cluster.md; a hub alone is a cluster of one) (env HEARTH_CLUSTER_MODE)")
	replicas := 0
	if v := os.Getenv("HEARTH_REPLICAS"); v != "" {
		replicas, _ = strconv.Atoi(v)
	}
	cmd.Flags().IntVar(&o.replicas, "replicas", replicas,
		"ap mode: copies of each row (N); 0 means min(2, storage members) (env HEARTH_REPLICAS)")
	var seeds []string
	if v := os.Getenv("HEARTH_GOSSIP_SEEDS"); v != "" {
		seeds = strings.Split(v, ",")
	}
	cmd.Flags().StringSliceVar(&o.gossipSeeds, "gossip-seeds", seeds,
		"ap mode: gossip addresses (host:port) of other members to find the cluster by; the --join hub's "+
			"is added (env HEARTH_GOSSIP_SEEDS)")
}

// checkMode checks --cluster-mode and --replicas.
func (o clusterOptions) checkMode() error {
	switch o.mode {
	case clusterModeRaft, "":
		return nil
	case clusterModeAP:
		if o.replicas < 0 {
			return errors.New("--replicas must be at least 1 (0 picks the default)")
		}
		if o.form {
			return errors.New("--cluster forms a Raft cluster; an ap hub forms its cluster on its own")
		}
		if o.gossipListen == "" {
			return errors.New("ap mode needs --gossip-listen: members replicate over it")
		}
		return nil
	}
	return fmt.Errorf("--cluster-mode %q: want raft or ap", o.mode)
}

// ap reports whether the hub runs in an AP cluster.
func (o clusterOptions) ap() bool { return o.mode == clusterModeAP }

// startAPNode opens the store as a member of an AP cluster. On a first start
// with --join it joins through that hub with the join token (its node
// certificate and the CA land in the data dir); without, the hub forms a
// cluster of one, creating its CA if it has none. Writes go through the
// node's replicator, reads to the members holding the rows.
func startAPNode(ctx context.Context, opts hubOptions, allowed cluster.RoleSet, agentURL string, log *slog.Logger) (
	*store.Store, *pki.CA, *cluster.APNode, error,
) {
	o := opts.cluster
	if err := cluster.CheckMode(opts.dataDir, clusterModeAP); err != nil {
		return nil, nil, nil, err
	}
	nodeID, err := cluster.NodeID(opts.dataDir, o.nodeID, hostnameOr("hub"))
	if err != nil {
		return nil, nil, nil, err
	}
	advertise, err := o.gossipAdvertiseAddr()
	if err != nil {
		return nil, nil, nil, err
	}
	_, statErr := os.Stat(filepath.Join(opts.dataDir, pki.CAKeyFile))
	hasCA := statErr == nil
	seeds := o.gossipSeeds
	if o.join != "" {
		if s, err := joinGossipSeed(o.join, o.gossipListen); err == nil {
			seeds = append(seeds, s)
		}
	}
	if !hasCA && o.join != "" {
		token := o.joinToken
		if token == "" {
			token = opts.joinTokenEnv
		}
		if token == "" {
			return nil, nil, nil, errors.New("--join needs a join token: set HEARTH_JOIN_TOKEN (or --join-token)")
		}
		if err := cluster.Join(ctx, cluster.JoinParams{
			URL: o.join, Token: token, DataDir: opts.dataDir, NodeID: nodeID, RaftAddress: advertise,
			AllowedRoles: allowed,
		}); err != nil {
			return nil, nil, nil, err
		}
		log.InfoContext(ctx, "joined the ap cluster", "node_id", nodeID, "via", o.join)
	}
	ca, err := pki.LoadOrCreateCA(opts.dataDir, time.Now())
	if err != nil {
		return nil, nil, nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", o.gossipListen)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("--gossip-listen %s: %w", o.gossipListen, err)
	}
	if host, port, err := net.SplitHostPort(advertise); err == nil && port == "0" {
		advertise = net.JoinHostPort(host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	}
	node, err := cluster.NewAPNode(ctx, cluster.APConfig{
		DataDir: opts.dataDir, NodeID: nodeID, CA: ca, Allowed: allowed,
		Listen: o.gossipListen, Listener: ln, Advertise: advertise, Seeds: seeds,
		Replicas: o.replicas, AgentURL: agentURL, Log: log,
	})
	if err != nil {
		_ = ln.Close()
		return nil, nil, nil, err
	}
	st, err := store.Open(ctx, filepath.Join(opts.dataDir, dbFile), node.StoreOptions()...)
	if err != nil {
		_ = ln.Close()
		return nil, nil, nil, err
	}
	if err := node.Bind(ctx, st); err != nil {
		_ = ln.Close()
		_ = st.Close()
		return nil, nil, nil, err
	}
	log.InfoContext(ctx, "ap cluster member", "node_id", nodeID, "gossip", advertise, "seeds", seeds)
	return st, ca, node, nil
}

// joinGossipSeed is the gossip address of the hub at joinURL: its host, at
// this hub's gossip port (every member is expected to gossip on one port).
func joinGossipSeed(joinURL, gossipListen string) (string, error) {
	u, err := url.Parse(joinURL)
	if err != nil {
		return "", err
	}
	_, port, err := net.SplitHostPort(gossipListen)
	if err != nil || port == "" || port == "0" {
		port = cluster.DefaultGossipPort
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// runAPMember waits for a first sync with the cluster, then records this
// hub's node certificate, applies HEARTH_ADMIN_PASSWORD (after the sync, so
// a new member does not replace the cluster's password) and says whether
// the cluster is highly available.
func runAPMember(ctx context.Context, node *cluster.APNode, setup func(context.Context) error, ready chan<- struct{}, log *slog.Logger) error {
	if err := node.WaitPeers(ctx, 30*time.Second); err != nil && ctx.Err() == nil {
		log.WarnContext(ctx, "starting alone: no other member of the ap cluster reached", "err", err)
	}
	if err := node.Replicator().WaitSynced(ctx, 30*time.Second); err != nil && ctx.Err() == nil {
		log.WarnContext(ctx, "first sync with the cluster incomplete; going on", "err", err)
	}
	if ctx.Err() != nil {
		return nil
	}
	if err := node.RecordNodeCert(ctx); err != nil {
		log.WarnContext(ctx, "record this hub's node certificate", "err", err)
	}
	if err := setup(ctx); err != nil {
		log.ErrorContext(ctx, "HEARTH_ADMIN_PASSWORD not applied", "err", err)
	}
	close(ready)
	st := node.Status()
	if !st.HighlyAvailable {
		log.WarnContext(ctx, "the ap cluster is not highly available: fewer than 2 storage members or N < 2",
			"storage_members", st.StorageMembers, "replicas", st.Replicas)
	} else {
		log.InfoContext(ctx, "caught up with the ap cluster", "storage_members", st.StorageMembers, "replicas", st.Replicas)
	}
	return nil
}
