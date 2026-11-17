// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
)

// ErrUnavailable is returned by a replicated Applier that cannot reach a
// cluster leader in time: the write did not happen and may be retried.
var ErrUnavailable = errors.New("cluster unavailable: no leader reachable")

// Hubs is the repository for cluster hub metadata: the agent-facing URL of
// each hub, keyed by its Raft node ID.
type Hubs struct{ s *Store }

// Hubs returns the cluster hub repository.
func (s *Store) Hubs() Hubs { return Hubs{s: s} }

// SetAgentURL records the agent-facing URL of hub nodeID.
func (r Hubs) SetAgentURL(ctx context.Context, nodeID, agentURL string) error {
	if _, err := r.s.apply(ctx, SetHubURL{NodeID: nodeID, AgentURL: agentURL}); err != nil {
		return fmt.Errorf("set agent URL of hub %s: %w", nodeID, err)
	}
	return nil
}

// AgentURLs returns the recorded agent-facing URL of every hub by node ID.
func (r Hubs) AgentURLs(ctx context.Context) (map[string]string, error) {
	rows, err := r.s.db.QueryContext(ctx, `SELECT node_id, agent_url FROM cluster_hubs`)
	if err != nil {
		return nil, fmt.Errorf("list hub URLs: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, u string
		if err := rows.Scan(&id, &u); err != nil {
			return nil, fmt.Errorf("list hub URLs: %w", err)
		}
		out[id] = u
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list hub URLs: %w", err)
	}
	return out, nil
}
