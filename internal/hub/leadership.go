// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"errors"
	"net"

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

// soloLeadership is a single hub: always the leader, and the only hub.
type soloLeadership struct{ urls []string }

func (soloLeadership) IsLeader() bool { return true }

func (s soloLeadership) LeaderAgentURL() string {
	if len(s.urls) == 0 {
		return ""
	}
	return s.urls[0]
}

func (s soloLeadership) AgentURLs() []string { return s.urls }

// leadershipOf returns cfg.Leadership, or for a single hub one that is always
// the leader and lists this hub's own agent URL, built from the first agent
// host and the agent port (nothing if no host is configured).
func leadershipOf(cfg Config) Leadership {
	if cfg.Leadership != nil {
		return cfg.Leadership
	}
	if len(cfg.AgentHosts) == 0 {
		return soloLeadership{}
	}
	port := cfg.AgentPort
	if port == "" {
		port = DefaultAgentPort
	}
	return soloLeadership{urls: []string{"https://" + net.JoinHostPort(cfg.AgentHosts[0], port)}}
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
