// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// clusterOptions are the hub's Raft flags. None is needed on a standalone hub.
type clusterOptions struct {
	// form makes this hub the first member of a new cluster.
	form       bool
	join       string
	joinToken  string
	nodeID     string
	raftListen string
	advertise  string
}

func addClusterFlags(cmd *cobra.Command, o *clusterOptions) {
	cmd.Flags().BoolVar(&o.form, "cluster", false,
		"form a new Raft cluster with this hub as its first member (from its current data); "+
			"remembered in the data dir, so later starts need no flag")
	cmd.Flags().StringVar(&o.join, "join", "",
		"join the cluster of the hub at this URL (e.g. https://hub-a:"+defaultPort+") with a join token "+
			"from `hearth cluster token create`; needs a fresh data dir")
	cmd.Flags().StringVar(&o.joinToken, "join-token", "",
		"cluster join token (prefer env HEARTH_JOIN_TOKEN, which keeps it out of the process list)")
	cmd.Flags().StringVar(&o.nodeID, "node-id", "",
		"this hub's cluster node ID (default: derived from the hostname, persisted in the data dir)")
	cmd.Flags().StringVar(&o.raftListen, "raft-listen", ":"+cluster.DefaultRaftPort,
		"address for Raft traffic between hubs (mutual TLS) in a cluster")
	cmd.Flags().StringVar(&o.advertise, "advertise", "",
		"host:port other hubs use to reach this hub's --raft-listen (default: this hostname and the Raft port)")
}

// clustered reports whether the hub runs as a Raft cluster member: it was
// told to form or join one, or its data dir already belongs to one.
func (o clusterOptions) clustered(dataDir string) bool {
	return o.form || o.join != "" || cluster.IsMember(dataDir)
}

func (o clusterOptions) advertiseAddr() (string, error) {
	if o.advertise != "" {
		if _, _, err := net.SplitHostPort(o.advertise); err != nil {
			return "", fmt.Errorf("--advertise %s: %w", o.advertise, err)
		}
		return o.advertise, nil
	}
	host, port, err := net.SplitHostPort(o.raftListen)
	if err != nil {
		return "", fmt.Errorf("--raft-listen %s: %w", o.raftListen, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = hostnameOr("localhost")
	}
	return net.JoinHostPort(host, port), nil
}

// startClusterNode opens the store as a Raft cluster member and starts the
// node. First, if asked to join and not joined yet, it runs the join: the
// node certificate and the cluster's CA, key included, land in the data dir.
// A member never migrates its database on its own: once it holds Raft state,
// the store must already be at this binary's schema version.
func startClusterNode(ctx context.Context, opts hubOptions, log *slog.Logger, onFatal func(error)) (
	*store.Store, *pki.CA, *cluster.Node, error,
) {
	o := opts.cluster
	if o.form && o.join != "" {
		return nil, nil, nil, errors.New("--cluster forms a new cluster and --join joins one: pick one")
	}
	firstStart := !cluster.IsMember(opts.dataDir)
	if !firstStart && (o.join != "" || o.form) {
		log.InfoContext(ctx, "this data dir already belongs to a cluster; ignoring --cluster/--join")
	}
	advertise, err := o.advertiseAddr()
	if err != nil {
		return nil, nil, nil, err
	}
	nodeID, err := cluster.NodeID(opts.dataDir, o.nodeID, hostnameOr("hub"))
	if err != nil {
		return nil, nil, nil, err
	}
	if firstStart && o.join != "" {
		token := o.joinToken
		if token == "" {
			token = opts.joinTokenEnv
		}
		if token == "" {
			return nil, nil, nil, errors.New("--join needs a join token: set HEARTH_JOIN_TOKEN (or --join-token)")
		}
		if err := cluster.Join(ctx, cluster.JoinParams{
			URL: o.join, Token: token, DataDir: opts.dataDir, NodeID: nodeID, RaftAddress: advertise,
		}); err != nil {
			return nil, nil, nil, err
		}
		log.InfoContext(ctx, "joined the cluster as a non-voter", "node_id", nodeID, "via", o.join)
	}

	// Only the hub that forms a cluster may create a CA; a member gets the
	// cluster's at join.
	ca, err := loadClusterCA(opts.dataDir, o.form && firstStart)
	if err != nil {
		return nil, nil, nil, err
	}
	node, err := cluster.New(cluster.Config{
		DataDir: opts.dataDir, NodeID: nodeID, Listen: o.raftListen, Advertise: advertise,
		CA: ca, Bootstrap: o.form, Log: log, OnFatal: onFatal,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	storeOpts := []store.Option{store.WithApplier(node.Bind)}
	if !firstStart {
		storeOpts = append(storeOpts, store.WithoutUpgrade())
	}
	st, err := store.Open(ctx, filepath.Join(opts.dataDir, dbFile), storeOpts...)
	if errors.Is(err, store.ErrSchemaMismatch) {
		return nil, nil, nil, fmt.Errorf("%w: a cluster member never migrates its database on its own; "+
			"run the hearth version the cluster runs (rolling upgrades: see docs/design/ha-hub.md)", err)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if err := node.Start(ctx); err != nil {
		_ = st.Close()
		return nil, nil, nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := node.WaitReady(waitCtx); err != nil {
		log.WarnContext(ctx, "no cluster leader yet; serving reads from local state", "err", err)
	}
	return st, ca, node, nil
}

func loadClusterCA(dataDir string, mayCreate bool) (*pki.CA, error) {
	if !mayCreate {
		if _, err := os.Stat(filepath.Join(dataDir, pki.CAKeyFile)); err != nil {
			return nil, fmt.Errorf("cluster member without a CA in %s (did a --join fail? start over with an empty "+
				"data dir and a new join token): %w", dataDir, err)
		}
	}
	return pki.LoadOrCreateCA(dataDir, time.Now())
}

// promoteUntilVoter asks the leader to make this joined hub a voter, retrying
// until it is one or ctx ends. Hubs that formed the cluster are voters already.
func promoteUntilVoter(ctx context.Context, node *cluster.Node, dataDir string, log *slog.Logger) error {
	for {
		voter, err := node.IsVoter()
		if err == nil && voter {
			return nil
		}
		if err == nil && node.Leader().ID != "" {
			if err := cluster.Promote(ctx, dataDir, node.ID()); err != nil {
				log.WarnContext(ctx, "promotion to voter failed; retrying", "err", err)
			} else {
				log.InfoContext(ctx, "promoted to cluster voter")
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}
