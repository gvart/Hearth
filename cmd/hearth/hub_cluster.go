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
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// clusterOptions are the hub's cluster flags. A hub started without any is a
// cluster of one.
type clusterOptions struct {
	join      string
	joinToken string
	nodeID    string
	// listen is the address members gossip and replicate over (mutual
	// TLS); advertise is the host:port other members dial for it.
	listen    string
	advertise string
	// ln, if set, is a listener already bound to listen (tests).
	ln net.Listener
	// seeds are the addresses of other members to find the cluster by.
	seeds []string
	// allowRoles is this host's --allow-roles, the roles it may take; empty
	// means the hub's own, master and storage.
	allowRoles string
	// replicas is N, the copies of each row; 0 means min(2, storage
	// members).
	replicas int
}

func addClusterFlags(cmd *cobra.Command, o *clusterOptions) {
	cmd.Flags().StringVar(&o.join, "join", "",
		"join the cluster of the hub at this URL (e.g. https://hub-a:"+defaultPort+") with a join token "+
			"from `hearth cluster token create`; needs a fresh data dir")
	cmd.Flags().StringVar(&o.joinToken, "join-token", "",
		"cluster join token (prefer env HEARTH_JOIN_TOKEN, which keeps it out of the process list)")
	cmd.Flags().StringVar(&o.nodeID, "node-id", "",
		"this hub's cluster node ID (default: derived from the hostname, persisted in the data dir)")
	listen := os.Getenv("HEARTH_CLUSTER_LISTEN")
	if listen == "" {
		listen = ":" + cluster.DefaultPort
	}
	cmd.Flags().StringVar(&o.listen, "cluster-listen", listen,
		"address for gossip and replication between the cluster's hubs (TCP, mutual TLS) (env HEARTH_CLUSTER_LISTEN)")
	cmd.Flags().StringVar(&o.advertise, "cluster-advertise", os.Getenv("HEARTH_CLUSTER_ADVERTISE"),
		"host:port other hubs use to reach this hub's --cluster-listen (default: this hostname and the "+
			"--cluster-listen port) (env HEARTH_CLUSTER_ADVERTISE)")
	cmd.Flags().StringSliceVar(&o.seeds, "cluster-seeds", splitList(os.Getenv("HEARTH_CLUSTER_SEEDS")),
		"cluster addresses (host:port) of other members to find the cluster by; the --join hub's is added "+
			"(env HEARTH_CLUSTER_SEEDS, comma-separated)")
	allow := os.Getenv("HEARTH_ALLOW_ROLES")
	if allow == "" {
		allow = cluster.HubRoles.String()
	}
	cmd.Flags().StringVar(&o.allowRoles, "allow-roles", allow,
		"cluster roles this host may take, comma-separated from storage and master (env HEARTH_ALLOW_ROLES)")
	replicas := 0
	if v := os.Getenv("HEARTH_REPLICAS"); v != "" {
		replicas, _ = strconv.Atoi(v)
	}
	cmd.Flags().IntVar(&o.replicas, "replicas", replicas,
		"copies of each row (N); 0 means min(2, storage members) (env HEARTH_REPLICAS)")
}

// check checks the cluster flags.
func (o clusterOptions) check() error {
	if o.replicas < 0 {
		return errors.New("--replicas must be at least 1 (0 picks the default)")
	}
	if o.listen == "" {
		return errors.New("--cluster-listen is empty: a hub's store replicates over it")
	}
	return nil
}

// allowedRoles parses --allow-roles; empty means the hub's roles.
func (o clusterOptions) allowedRoles() (cluster.RoleSet, error) {
	if strings.TrimSpace(o.allowRoles) == "" {
		return cluster.HubRoles, nil
	}
	allowed, err := cluster.ParseRoles(o.allowRoles)
	if err != nil {
		return 0, fmt.Errorf("--allow-roles: %w", err)
	}
	return allowed, nil
}

// advertiseAddr is --cluster-advertise, or this hostname (the listen host
// when it is a specific address) with the --cluster-listen port.
func (o clusterOptions) advertiseAddr(ctx context.Context) (string, error) {
	if o.advertise != "" {
		if _, _, err := net.SplitHostPort(o.advertise); err != nil {
			return "", fmt.Errorf("--cluster-advertise %s: %w", o.advertise, err)
		}
		return o.advertise, nil
	}
	host, port, err := net.SplitHostPort(o.listen)
	if err != nil {
		return "", fmt.Errorf("--cluster-listen %s: %w", o.listen, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = dialableHost(ctx, hostnameOr("localhost"))
	}
	return net.JoinHostPort(host, port), nil
}

// dialableHost is host, unless it resolves only to loopback addresses (as a
// hostname does with Debian's 127.0.1.1 in /etc/hosts), which other members
// cannot dial: then this host's first private address, or 127.0.0.1 on a
// host with none, where the hub stays a cluster of one until it gets one.
func dialableHost(ctx context.Context, host string) string {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err == nil {
		for _, ip := range ips {
			if !ip.IsLoopback() {
				return host
			}
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
				return n.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// startClusterNode opens the store as a member of the hub's cluster. On a
// first start with --join it joins through that hub with the join token (its
// node certificate and the CA land in the data dir); without, the hub forms a
// cluster of one, creating its CA if it has none. Writes go through the
// node's replicator, reads to the members holding the rows.
func startClusterNode(ctx context.Context, opts hubOptions, allowed cluster.RoleSet, agentURL string, log *slog.Logger) (
	*store.Store, *pki.CA, *cluster.APNode, error,
) {
	o := opts.cluster
	nodeID, err := cluster.NodeID(opts.dataDir, o.nodeID, hostnameOr("hub"))
	if err != nil {
		return nil, nil, nil, err
	}
	advertise, err := o.advertiseAddr(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	// A member that is no master holds the CA certificate only.
	_, statErr := os.Stat(filepath.Join(opts.dataDir, pki.CACertFile))
	hasCA := statErr == nil
	seeds := o.seeds
	if o.join != "" {
		if s, err := joinSeed(o.join, o.listen); err == nil {
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
			URL: o.join, Token: token, DataDir: opts.dataDir, NodeID: nodeID, Address: advertise,
			AllowedRoles: allowed,
		}); err != nil {
			return nil, nil, nil, err
		}
		log.InfoContext(ctx, "joined the cluster", "node_id", nodeID, "via", o.join)
	} else if !hasCA && !allowed.Has(cluster.RoleMaster) {
		return nil, nil, nil, errors.New("the first hub of a cluster is a master: allow the master role " +
			"(--allow-roles), or join a cluster with --join")
	}
	ca, err := pki.LoadCA(opts.dataDir, time.Now())
	if err != nil {
		return nil, nil, nil, err
	}
	ln := o.ln
	if ln == nil {
		if ln, err = (&net.ListenConfig{}).Listen(ctx, "tcp", o.listen); err != nil {
			return nil, nil, nil, fmt.Errorf("--cluster-listen %s: %w", o.listen, err)
		}
	}
	if host, port, err := net.SplitHostPort(advertise); err == nil && port == "0" {
		advertise = net.JoinHostPort(host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	}
	node, err := cluster.NewAPNode(ctx, cluster.APConfig{
		DataDir: opts.dataDir, NodeID: nodeID, CA: ca, Allowed: allowed,
		Listen: o.listen, Listener: ln, Advertise: advertise, Seeds: seeds,
		Replicas: o.replicas, AgentURL: agentURL, Log: log, ConfigSource: cluster.HostFlagsSource(opts.dangerousAutomations),
	})
	if err != nil {
		_ = ln.Close()
		return nil, nil, nil, err
	}
	if !node.Roles().Has(cluster.RoleMaster) && ca.HasKey() {
		// Demoted, or no longer allowed the role: the key goes.
		if err := ca.DropKey(); err != nil {
			_ = ln.Close()
			return nil, nil, nil, fmt.Errorf("delete the CA key of a member that is no master: %w", err)
		}
		log.InfoContext(ctx, "not a master: deleted the CA key")
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
	log.InfoContext(ctx, "cluster member", "node_id", nodeID, "address", advertise, "seeds", seeds)
	return st, ca, node, nil
}

// joinSeed is the cluster address of the hub at joinURL: its host, at this
// hub's cluster port (every member is expected to listen on one port).
func joinSeed(joinURL, listen string) (string, error) {
	u, err := url.Parse(joinURL)
	if err != nil {
		return "", err
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" || port == "0" {
		port = cluster.DefaultPort
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// runClusterMember waits for a first sync with the cluster, then records this
// hub's node certificate, applies HEARTH_ADMIN_PASSWORD (after the sync, so
// a new member does not replace the cluster's password) and says whether
// the cluster is highly available. caughtUp says, once ready is closed,
// whether it found the cluster and finished the sync.
func runClusterMember(ctx context.Context, node *cluster.APNode, setup func(context.Context) error, ready chan<- struct{},
	caughtUp *atomic.Bool, log *slog.Logger,
) error {
	found := true
	if err := node.WaitPeers(ctx, 30*time.Second); err != nil && ctx.Err() == nil {
		log.WarnContext(ctx, "starting alone: no other member of the cluster reached; critical writes are "+
			"acknowledged with one copy until one is", "err", err)
		found = false
		node.StartAlone()
	}
	synced := true
	if err := node.Replicator().WaitSynced(ctx, 30*time.Second); err != nil && ctx.Err() == nil {
		log.WarnContext(ctx, "first sync with the cluster incomplete; going on", "err", err)
		synced = false
	}
	if ctx.Err() != nil {
		return nil
	}
	caughtUp.Store(found && synced)
	if err := node.RecordNodeCert(ctx); err != nil {
		log.WarnContext(ctx, "record this hub's node certificate", "err", err)
	}
	if err := setup(ctx); err != nil {
		log.ErrorContext(ctx, "HEARTH_ADMIN_PASSWORD not applied", "err", err)
	}
	close(ready)
	st := node.Status()
	if !st.HighlyAvailable {
		log.WarnContext(ctx, "the cluster is not highly available: fewer than 2 storage members or N < 2",
			"storage_members", st.StorageMembers, "replicas", st.Replicas)
	} else {
		log.InfoContext(ctx, "caught up with the cluster", "storage_members", st.StorageMembers, "replicas", st.Replicas)
	}
	return nil
}
