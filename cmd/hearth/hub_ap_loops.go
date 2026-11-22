// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/integrations/beszel"
	"github.com/gvart/hearth/internal/integrations/talos"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// apLoops are the loops each runs on one master of the cluster.
type apLoops struct {
	agents      *hub.Agents
	reg         *hub.Registry
	st          *store.Store
	pol         *policy.Engine
	automations *automation.Runtime
	runbooks    *automation.Runbooks
	scanner     *discovery.Scanner
	importer    *discovery.Importer
	beszel      *beszel.Reader
	talos       *talos.Reader
	backups     *backup.Scheduler
	ready       <-chan struct{}
	log         *slog.Logger

	// scheduledScans runs scanner on its schedule (--discover-subnet).
	scheduledScans bool
	// lanName announces discovery.LANName over mDNS (--no-lan-name).
	lanName bool
}

// runAPLoops runs those loops on a master of an AP cluster
// (docs/design/ap-cluster.md §6). Presence: each master sweeps the devices
// it owns (hub.PresenceOwner). Automations, runbook runs and the approval
// sweep run on every master, each on the items it owns on the ring of
// masters. Network discovery, the network import, scheduled backups, the
// removal of members down for good and the mDNS announcement of
// discovery.LANName run on the one master owning their key, and so does
// the promotion that keeps --keep-masters masters; during a partition, one
// may run on both sides (the removal and the promotion guard themselves:
// only a side that sees a majority acts).
func runAPLoops(ctx context.Context, g *errgroup.Group, node *cluster.APNode, l apLoops) {
	ring := node.Masters()
	g.Go(func() error {
		node.Announce(ctx)
		return nil
	})
	g.Go(func() error {
		return l.reg.RunOwned(ctx, hub.PresenceOwner(l.agents, l.st.DeviceRoutes(), ring, hub.DefaultOfflineAfter, time.Now))
	})
	// Agents already streaming learn a master that joins or goes.
	hubsChanged, unsubscribeHubs := ring.Subscribe()
	g.Go(func() error {
		defer unsubscribeHubs()
		return l.agents.RunHubsPush(ctx, node.AgentURLs, hubsChanged)
	})
	g.Go(func() error { return l.automations.Run(ctx) })
	g.Go(func() error { return l.runbooks.Run(ctx) })
	g.Go(func() error { return l.pol.RunApprovalSweep(ctx, l.log) })
	singleton := func(key string, run func(context.Context) error) {
		changed, unsubscribe := ring.Subscribe()
		g.Go(func() error {
			defer unsubscribe()
			return automation.RunWhileLeading(ctx, ring.Singleton("loop/"+key, l.ready), changed,
				l.log.With("component", key), run)
		})
	}
	if l.scheduledScans {
		singleton("discovery", l.scanner.Run)
	}
	if l.importer != nil {
		singleton("network-import", l.importer.Run)
	}
	// What Beszel and Talos reads find is kept in memory and served by the
	// hub that read it: every master reads, as every hub reads Kubernetes.
	if l.beszel != nil {
		g.Go(func() error { return l.beszel.Run(ctx) })
	}
	if l.talos != nil {
		g.Go(func() error { return l.talos.Run(ctx) })
	}
	if l.backups != nil {
		singleton("backup", l.backups.Run)
	}
	// One master removes the members down for --member-dead-after; each
	// member keeps its own record of who is down (deadmembers.go).
	if node.MemberDeadAfter() > 0 {
		singleton("dead-members", func(ctx context.Context) error { return node.RunDeadMemberRemoval(ctx, l.pol) })
	}
	// One master promotes a hub-eligible storage member when fewer than
	// --keep-masters masters are left (keepmasters.go).
	if node.KeepMasters() > 0 {
		singleton("keep-masters", func(ctx context.Context) error { return node.RunKeepMasters(ctx, l.pol) })
	}
	if l.lanName {
		a := &discovery.Announcer{Name: discovery.LANName, Log: l.log.With("component", "lan-name")}
		singleton("lan-name", a.Run)
	}
}
