// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"

	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
)

// Configuration drift.
//
// The automations and runbooks directories, notify.yaml and policy.yaml live on each hub and
// are not replicated. Each hub digests them and serves the digests to the other
// members through ClusterService.ConfigDigests, over the hub mTLS channel. A
// DriftReport says which items differ on which hubs; it never holds a digest,
// and neither does anything that is logged.

// The configuration items hubs compare.
const (
	ConfigPolicy      = "policy.yaml"
	ConfigNotify      = "notify.yaml"
	ConfigAutomations = "automations"
	ConfigRunbooks    = "runbooks"
)

// configItems are the items of a DriftReport. An item a newer hub reports
// beyond these is ignored, and an item an older hub does not report is
// unknown for that hub.
var configItems = []string{ConfigPolicy, ConfigNotify, ConfigAutomations, ConfigRunbooks}

// Item states of a DriftReport.
const (
	// DriftInSync means every hub reported the same digest.
	DriftInSync = "in_sync"
	// DriftDiffers means at least two hubs reported different digests.
	DriftDiffers = "differs"
	// DriftUnknown means no two hubs differ, but some hub did not report.
	DriftUnknown = "unknown"
)

// Reasons a hub did not report its digests.
const (
	// DriftUnreachable means the hub did not answer: it is down, still
	// starting, or refused the call.
	DriftUnreachable = "unreachable"
	// DriftOlderVersion means the hub's Hearth predates digest reports.
	DriftOlderVersion = "older_version"
	// DriftNotReported means the hub answered without digests.
	DriftNotReported = "not_reported"
)

// configDigestsTimeout bounds how long one hub's digests are waited for.
const configDigestsTimeout = 3 * time.Second

// ConfigSource returns this hub's digest of each configuration item. An item
// it cannot read is left out, which the other hubs show as unknown.
type ConfigSource func() map[string]string

// SetConfigSource sets where this hub's digests come from. Until it is set
// the hub reports none.
func (n *Node) SetConfigSource(src ConfigSource) { n.configSource.Store(&src) }

func (n *Node) localDigests() map[string]string {
	src := n.configSource.Load()
	if src == nil {
		return nil
	}
	return (*src)()
}

// DriftHub says whether one hub reported its digests.
type DriftHub struct {
	ID       string `json:"id"`
	Reported bool   `json:"reported"`
	// Reason says why it did not report: one of the Drift reason constants.
	Reason string `json:"reason,omitempty"`
}

// DriftItem is the state of one configuration item across the hubs.
type DriftItem struct {
	Item string `json:"item"`
	// Status is DriftInSync, DriftDiffers or DriftUnknown.
	Status string `json:"status"`
	// Groups holds the hubs that reported this item, one group per distinct
	// content, the largest group first. Which group is right is the
	// operator's call: a majority proves nothing about a policy.
	Groups [][]string `json:"groups"`
	// Unknown holds the hubs that did not report this item.
	Unknown []string `json:"unknown"`
}

// DriftReport compares the configuration of every hub in the Raft
// configuration. It holds no digests and no file contents.
type DriftReport struct {
	Hubs  []DriftHub  `json:"hubs"`
	Items []DriftItem `json:"items"`
}

// ConfigDrift compares this hub's configuration digests with those of every
// other hub in the Raft configuration, asked in parallel. A hub that does not
// answer counts as unknown, never as differing.
func (n *Node) ConfigDrift(ctx context.Context) (DriftReport, error) {
	if n.raft == nil {
		return DriftReport{}, errors.New("cluster: node not started")
	}
	cf := n.raft.GetConfiguration()
	if err := cf.Error(); err != nil {
		return DriftReport{}, fmt.Errorf("read the cluster configuration: %w", err)
	}
	servers := cf.Configuration().Servers
	urls := n.hubURLs(ctx)
	hubs := make([]DriftHub, len(servers))
	digests := make([]map[string]string, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		hubs[i].ID = string(s.ID)
		wg.Go(func() {
			d, reason := n.hubDigests(ctx, urls, string(s.ID), string(s.Address))
			digests[i], hubs[i].Reason, hubs[i].Reported = d, reason, reason == ""
		})
	}
	wg.Wait()
	return compareDigests(hubs, digests), nil
}

// hubDigests returns one hub's digests, or why it has none.
func (n *Node) hubDigests(ctx context.Context, urls map[string]string, id, addr string) (map[string]string, string) {
	var digests map[string]string
	if id == n.cfg.NodeID {
		digests = n.localDigests()
	} else {
		base := n.agentURL(urls, id, addr)
		if base == "" {
			return nil, DriftUnreachable
		}
		ctx, cancel := context.WithTimeout(ctx, configDigestsTimeout)
		defer cancel()
		resp, err := clusterv1connect.NewClusterServiceClient(n.fwdHTTP, base).
			ConfigDigests(ctx, connect.NewRequest(&clusterv1.ConfigDigestsRequest{}))
		if err != nil {
			var ce *connect.Error
			if errors.As(err, &ce) && ce.Code() == connect.CodeUnimplemented {
				return nil, DriftOlderVersion
			}
			n.log.DebugContext(ctx, "cannot read a hub's configuration digests", "hub", id, "err", err)
			return nil, DriftUnreachable
		}
		digests = resp.Msg.GetDigests()
	}
	if len(digests) == 0 {
		return nil, DriftNotReported
	}
	return digests, ""
}

// compareDigests builds the report from each hub's digests; digests[i] belongs
// to hubs[i].
func compareDigests(hubs []DriftHub, digests []map[string]string) DriftReport {
	report := DriftReport{Hubs: hubs, Items: make([]DriftItem, 0, len(configItems))}
	for _, item := range configItems {
		byDigest := map[string][]string{}
		unknown := []string{}
		for i, h := range hubs {
			if d := digests[i][item]; d != "" {
				byDigest[d] = append(byDigest[d], h.ID)
			} else {
				unknown = append(unknown, h.ID)
			}
		}
		slices.Sort(unknown)
		groups := slices.Collect(maps.Values(byDigest))
		for _, g := range groups {
			slices.Sort(g)
		}
		slices.SortFunc(groups, func(a, b []string) int {
			return cmp.Or(cmp.Compare(len(b), len(a)), cmp.Compare(a[0], b[0]))
		})
		status := DriftInSync
		switch {
		case len(groups) > 1:
			status = DriftDiffers
		case len(unknown) > 0:
			status = DriftUnknown
		}
		report.Items = append(report.Items, DriftItem{Item: item, Status: status, Groups: groups, Unknown: unknown})
	}
	return report
}

// ConfigDigests reports this hub's configuration digests to a member (see
// Node.ConfigDrift). Every member serves it, leader or not.
func (s *JoinServer) ConfigDigests(ctx context.Context, _ *connect.Request[clusterv1.ConfigDigestsRequest]) (*connect.Response[clusterv1.ConfigDigestsResponse], error) {
	if _, err := s.memberPeer(ctx); err != nil {
		return nil, err
	}
	return connect.NewResponse(&clusterv1.ConfigDigestsResponse{Digests: s.node.localDigests()}), nil
}
