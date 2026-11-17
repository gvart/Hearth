// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"errors"

	"connectrpc.com/connect"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Leadership tells the hub whether it is the cluster leader, and where agents
// find the leader and every other hub. Only the leader serves AgentService and
// EnrollService; followers refuse them with a NotLeader error detail that names
// the leader. Implementations must be safe for concurrent use.
type Leadership interface {
	// IsLeader reports whether this hub is the leader now.
	IsLeader() bool
	// LeaderAgentURL is the leader's agent-facing URL (https://host:port), or
	// "" while no leader is known.
	LeaderAgentURL() string
	// AgentURLs are the agent-facing URLs of every hub in the cluster, this
	// one and the leader included.
	AgentURLs() []string
}

// soloLeadership is a single hub: always the leader, and it lists no hubs,
// so agents keep only the URL they joined with.
type soloLeadership struct{}

func (soloLeadership) IsLeader() bool         { return true }
func (soloLeadership) LeaderAgentURL() string { return "" }
func (soloLeadership) AgentURLs() []string    { return nil }

// leadershipOf returns cfg.Leadership, or soloLeadership for a single hub.
func leadershipOf(cfg Config) Leadership {
	if cfg.Leadership != nil {
		return cfg.Leadership
	}
	return soloLeadership{}
}

// notLeaderError is the error a follower returns to agents: FailedPrecondition
// with a NotLeader detail naming the leader and every hub. FailedPrecondition,
// not Unavailable, because retrying this hub cannot succeed until leadership
// changes; the client must go elsewhere, and the detail says where.
func notLeaderError(l Leadership) error {
	err := connect.NewError(connect.CodeFailedPrecondition, errors.New("this hub is not the cluster leader"))
	if d, derr := connect.NewErrorDetail(&agentv1.NotLeader{
		LeaderUrl: l.LeaderAgentURL(),
		Hubs:      l.AgentURLs(),
	}); derr == nil {
		err.AddDetail(d)
	}
	return err
}
