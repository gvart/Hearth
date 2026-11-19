// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/raft"

	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// Rolling schema migrations.
//
// A member's database stays at the cluster's schema whatever binary it runs,
// as long as the binary supports that schema (store.WithoutUpgrade). Each hub
// reports its schema live through ClusterService.SchemaInfo: the version its
// database is at and the newest its binary supports, so a hub restarted with
// a new binary reports the new maximum at once. MigrateSchema asks every hub
// in the Raft configuration, voters and non-voters, and proposes
// store.MigrateSchema only if all of them support the target; every node's
// state machine then runs the migrations in log order.

// schemaInfoTimeout bounds how long the leader waits for one hub's schema.
const schemaInfoTimeout = 3 * time.Second

// statusSchemaTimeout bounds how long StatusWithSchemas waits for the hubs.
const statusSchemaTimeout = time.Second

// ErrSchemaUnsupported refuses a migration to a schema that some hub's
// binary does not support, or whose schema could not be read.
var ErrSchemaUnsupported = errors.New("not every hub supports the target schema")

// errMigrateViaLog refuses MigrateSchema through Apply, ApplyOrForward and
// Forward: it must pass the support check of MigrateSchema first.
var errMigrateViaLog = errors.New("migrate_schema is proposed only by `hearth cluster migrate`, " +
	"which checks that every hub supports the target schema")

// SchemaInfo is one hub's store schema.
type SchemaInfo struct {
	// Current is the schema version its database is at.
	Current int64 `json:"current"`
	// Max is the newest schema version its binary supports.
	Max int64 `json:"max"`
}

// HubSchema is a member hub's schema as this node could read it.
type HubSchema struct {
	ID     string
	Schema SchemaInfo
	// Err is set when the hub's schema could not be read.
	Err error
}

// LocalSchema returns this hub's schema.
func (n *Node) LocalSchema(ctx context.Context) (SchemaInfo, error) {
	v, err := n.store.SchemaVersion(ctx)
	if err != nil {
		return SchemaInfo{}, err
	}
	return SchemaInfo{Current: v, Max: n.store.MaxSchemaVersion()}, nil
}

// HubSchemas returns the schema of every hub in the Raft configuration, in
// configuration order: this hub's from its store, the others' from their
// ClusterService, asked in parallel.
func (n *Node) HubSchemas(ctx context.Context) ([]HubSchema, error) {
	if n.raft == nil {
		return nil, errors.New("cluster: node not started")
	}
	cf := n.raft.GetConfiguration()
	if err := cf.Error(); err != nil {
		return nil, fmt.Errorf("read the cluster configuration: %w", err)
	}
	servers := cf.Configuration().Servers
	urls := n.hubURLs(ctx)
	out := make([]HubSchema, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		out[i].ID = string(s.ID)
		wg.Go(func() {
			out[i].Schema, out[i].Err = n.hubSchema(ctx, urls, string(s.ID), string(s.Address))
		})
	}
	wg.Wait()
	return out, nil
}

func (n *Node) hubSchema(ctx context.Context, urls map[string]string, id, addr string) (SchemaInfo, error) {
	if id == n.cfg.NodeID {
		return n.LocalSchema(ctx)
	}
	base := n.agentURL(urls, id, addr)
	if base == "" {
		return SchemaInfo{}, errors.New("its URL is unknown")
	}
	hc, err := n.clusterHTTP(ctx)
	if err != nil {
		return SchemaInfo{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, schemaInfoTimeout)
	defer cancel()
	resp, err := clusterv1connect.NewClusterServiceClient(hc, base).
		SchemaInfo(ctx, connect.NewRequest(&clusterv1.SchemaInfoRequest{}))
	if err != nil {
		var ce *connect.Error
		if errors.As(err, &ce) && ce.Code() == connect.CodeUnimplemented {
			return SchemaInfo{}, errors.New("its hearth predates schema reports")
		}
		return SchemaInfo{}, err
	}
	return SchemaInfo{Current: resp.Msg.GetCurrent(), Max: resp.Msg.GetMax()}, nil
}

// MigrateSchema migrates the cluster's schema to version to, on the leader
// or forwarded to it like RemoveMember, and returns the version the cluster
// was at. The leader refuses with ErrSchemaUnsupported, naming the hubs,
// unless every hub in the configuration reports a binary that supports to,
// and with store.ErrSchemaNotNewer unless to is newer than the cluster's
// schema. The caller makes the policy decision.
func (n *Node) MigrateSchema(ctx context.Context, to int64) (int64, error) {
	var from int64
	err := n.onLeader(ctx, fmt.Sprintf("migrate to schema %d", to), func() error {
		var err error
		from, err = n.migrateLocal(ctx, to)
		return err
	}, func(ctx context.Context, c clusterv1connect.ClusterServiceClient) error {
		resp, err := c.MigrateSchema(ctx, connect.NewRequest(&clusterv1.MigrateSchemaRequest{To: to}))
		if err == nil {
			from = resp.Msg.GetFrom()
		}
		return err
	})
	return from, err
}

func (n *Node) migrateLocal(ctx context.Context, to int64) (int64, error) {
	from, err := n.store.SchemaVersion(ctx)
	if err != nil {
		return 0, err
	}
	if to <= from {
		return from, fmt.Errorf("cannot migrate to schema %d: %w: the cluster is at %d", to, store.ErrSchemaNotNewer, from)
	}
	hubs, err := n.HubSchemas(ctx)
	if err != nil {
		return from, err
	}
	var lacking []string
	for _, h := range hubs {
		switch {
		case h.Err != nil:
			lacking = append(lacking, fmt.Sprintf("%s (cannot read its schema: %v)", h.ID, h.Err))
		case h.Schema.Max < to:
			lacking = append(lacking, fmt.Sprintf("%s (supports up to %d)", h.ID, h.Schema.Max))
		}
	}
	if len(lacking) > 0 {
		return from, fmt.Errorf("cannot migrate to schema %d: %w: %s; upgrade those hubs first, "+
			"or remove a hub that is gone for good", to, ErrSchemaUnsupported, strings.Join(lacking, ", "))
	}
	_, _, err = n.propose(ctx, store.MigrateSchema{To: to})
	var nl *ErrNotLeader
	if errors.As(err, &nl) {
		return from, raft.ErrNotLeader
	}
	if err != nil {
		return from, err
	}
	n.log.InfoContext(ctx, "migrated the cluster schema", "from", from, "to", to)
	return from, nil
}

// SchemaInfo reports this hub's schema to a member (see Node.HubSchemas).
// Every member serves it, leader or not.
func (s *JoinServer) SchemaInfo(ctx context.Context, _ *connect.Request[clusterv1.SchemaInfoRequest]) (*connect.Response[clusterv1.SchemaInfoResponse], error) {
	if _, err := s.memberPeer(ctx); err != nil {
		return nil, err
	}
	si, err := s.node.LocalSchema(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "read the schema version", "err", err)
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("cannot read the schema version"))
	}
	return connect.NewResponse(&clusterv1.SchemaInfoResponse{Current: si.Current, Max: si.Max}), nil
}

// MigrateSchema migrates the cluster's schema on behalf of a member hub (see
// Node.MigrateSchema).
func (s *JoinServer) MigrateSchema(ctx context.Context, req *connect.Request[clusterv1.MigrateSchemaRequest]) (*connect.Response[clusterv1.MigrateSchemaResponse], error) {
	if !s.node.IsLeader() {
		return nil, s.notLeaderError()
	}
	from, err := s.memberPeer(ctx)
	if err != nil {
		return nil, err
	}
	was, err := s.node.migrateLocal(ctx, req.Msg.GetTo())
	if err != nil {
		return nil, s.memberError(err)
	}
	s.log.InfoContext(ctx, "schema migration requested by a member", "to", req.Msg.GetTo(), "from_hub", from)
	return connect.NewResponse(&clusterv1.MigrateSchemaResponse{From: was}), nil
}
