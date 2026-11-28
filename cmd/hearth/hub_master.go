// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// apMember is what the master layer of a member shares with the member
// (runClusterHub): its store, CA and node, the ready channel closed after the
// first sync, and the member's context, which outlives the layer.
type apMember struct {
	st   *store.Store
	ca   *pki.CA
	node *cluster.APNode
	// ring seals the audit entries the member appends and checks those it
	// reads (#387); it holds keys only while the member is a master.
	ring  *pki.AuditKeyring
	ready chan struct{}
	// caughtUp, read once ready is closed, is whether the member found the
	// cluster it was told to join and copied its rows.
	caughtUp *atomic.Bool
	ctx      context.Context
}

// runClusterHub runs a cluster member: its store, gossip, replication
// and control socket all along; the master layer (API, UI, agents,
// enrollments, the masters' loops: runHub) while it is a master. A
// promotion to master starts the layer, a demotion stops it, and the
// member's agents move to the other masters.
func runClusterHub(ctx context.Context, opts hubOptions, allowed cluster.RoleSet, log *slog.Logger) error {
	hosts := hubHosts(ctx, opts.hosts, opts.lanName, log)
	var agentURL string
	if _, port, err := net.SplitHostPort(opts.listen); err == nil && port != "0" {
		agentURL = "https://" + net.JoinHostPort(hosts[0], port)
	}
	st, ca, node, err := startClusterNode(ctx, opts, allowed, agentURL, log)
	if errors.Is(err, errNothingToJoin) {
		// The installer's hub service on a device that is no hub: done.
		log.InfoContext(ctx, err.Error(), "join_file", opts.cluster.joinFile)
		return nil
	}
	if err != nil {
		return err
	}
	defer st.Close()
	ring, err := pki.NewAuditKeyring(ca)
	if err != nil {
		return err
	}
	st.SetAuditSealer(ring)
	ready := make(chan struct{})
	caughtUp := new(atomic.Bool)
	// HEARTH_ADMIN_PASSWORD is applied with an engine of its own: the
	// action is fixed, so no configuration applies.
	setupPol := policy.NewWithConfig(st.Audit(), st.Approvals(), policy.Config{})
	g, gctx := errgroup.WithContext(ctx)
	// Set before any goroutine starts: the member's closure reads opts.
	opts.apm = &apMember{st: st, ca: ca, node: node, ring: ring, ready: ready, caughtUp: caughtUp, ctx: gctx}
	g.Go(func() error { return node.Run(gctx) })
	g.Go(func() error { return cluster.ServeAPControl(gctx, opts.dataDir, node, log) })
	g.Go(func() error {
		return runClusterMember(gctx, node, func(ctx context.Context) error {
			return ensureAdminPassword(ctx, st, setupPol, opts, log)
		}, ready, caughtUp, log)
	})
	g.Go(func() error { return runMasterLayer(gctx, opts, log) })
	return g.Wait()
}

// runMasterLayer runs runHub while the member is a master, until ctx ends.
func runMasterLayer(ctx context.Context, opts hubOptions, log *slog.Logger) error {
	node := opts.apm.node
	changes, stop := node.RoleChanges()
	defer stop()
	for {
		if !node.IsMaster() {
			log.InfoContext(ctx, "not a master: this member serves no API, UI or agents", "roles", node.Roles())
			select {
			case <-ctx.Done():
				return nil
			case <-changes:
			}
			continue
		}
		lctx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- runHub(lctx, opts, log) }()
		err := waitMasterLayer(ctx, node, changes, done, cancel)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		log.InfoContext(ctx, "demoted from master: stopped serving the API, UI and agents")
		// The listeners given were closed with the layer: the next one
		// binds its own.
		opts.agentLn, opts.webLn = nil, nil
	}
}

// waitMasterLayer waits until the layer running into done ends, stopping
// it when the member is no longer a master or ctx ends.
func waitMasterLayer(ctx context.Context, node *cluster.APNode, changes <-chan struct{}, done <-chan error,
	cancel context.CancelFunc,
) error {
	defer cancel()
	for {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			cancel()
			return <-done
		case <-changes:
			if !node.IsMaster() {
				cancel()
				return <-done
			}
		}
	}
}

// apClusterAdmin is an AP member as the hub API's hub.ClusterAdmin.
type apClusterAdmin struct{ node *cluster.APNode }

func (a apClusterAdmin) Status(ctx context.Context) any { return a.node.StatusWithSafeStop(ctx) }

func (a apClusterAdmin) Promote(ctx context.Context, member, role string) (any, error) {
	return a.node.Promote(ctx, member, cluster.Role(role))
}

func (a apClusterAdmin) Demote(ctx context.Context, member, role string) (any, error) {
	return a.node.Demote(ctx, member, cluster.Role(role))
}

func (a apClusterAdmin) Remove(ctx context.Context, member string) (any, error) {
	return a.node.RemoveMember(ctx, member)
}

func (apClusterAdmin) ErrorKind(err error) string { return cluster.RoleErrorKind(err) }

// apClusterCA is an AP member as the hub API's hub.ClusterCA.
type apClusterCA struct{ node *cluster.APNode }

func (a apClusterCA) CAStatus(ctx context.Context) (hub.ClusterCAJSON, error) {
	st, err := a.node.CAStatus(ctx)
	if err != nil {
		return hub.ClusterCAJSON{}, err
	}
	status := a.node.Status()
	out := hub.ClusterCAJSON{NodeID: status.NodeID, Hubs: []hub.MemberCAJSON{}, OldDevices: st.OldDevices}
	if rot := st.Rotation; rot != nil {
		out.Rotation = &hub.CARotationJSON{
			NewCAFP: rot.NewCAFP, OldCAFP: rot.OldCAFP, Stage: rot.Stage, Active: rot.Active(),
			StartedAt: rot.StartedAt, UpdatedAt: rot.UpdatedAt, Owner: rot.Owner,
		}
		if rot.Owner != "" {
			out.Rotation.OwnerAlive = a.node.Masters().Live(rot.Owner)
			out.Rotation.OwnerURL = a.node.AgentURLOf(ctx, rot.Owner)
		}
	}
	master := map[string]bool{}
	for _, m := range status.Members {
		master[m.ID] = m.Roles.Has(cluster.RoleMaster)
	}
	for _, h := range st.Hubs {
		out.Hubs = append(out.Hubs, hub.MemberCAJSON{
			ID: h.ID, Master: master[h.ID], Serving: h.Info.ServingFP, Next: h.Info.NextFP,
			HasNextKey: h.Info.HasNextKey, HasNextCert: h.Info.HasNextCert, CutOver: h.Info.CutOver, Error: h.Error,
		})
	}
	return out, nil
}

func (a apClusterCA) ChangeCA(ctx context.Context, op, actorKind, actorID string, precheck func(context.Context) error) error {
	_, err := a.node.ChangeCAAs(ctx, cluster.CARequest{Op: op}, cluster.CAActor{Kind: actorKind, ID: actorID, Precheck: precheck})
	return err
}

func (apClusterCA) CAErrorKind(err error) string { return cluster.CAErrorKind(err) }

// apDryRun is the result of a dry-run role change from the CLI.
type apDryRun struct {
	Decision string `json:"decision"`
}

// apRoleChanges runs the CLI's role changes (cluster.RoleChangeRequest) as
// the admin, through pol: this master's engine, which refuses while it is
// isolated.
func apRoleChanges(pol *policy.Engine, admin hub.ClusterAdmin) cluster.RoleChangeFunc {
	return func(ctx context.Context, req cluster.RoleChangeRequest) (any, error) {
		c := hub.ClusterChange{Op: req.Op, Member: req.Member, Role: req.Role}
		out, err := hub.DoClusterChange(ctx, pol, admin, policy.ActorAdmin, req.Actor, c, req.DryRun, nil, nil)
		if err != nil || !req.DryRun {
			return out, err
		}
		decision, _ := pol.Check(hub.ClusterChangeRequest(c, policy.ActorAdmin, req.Actor))
		return apDryRun{Decision: decision}, nil
	}
}
