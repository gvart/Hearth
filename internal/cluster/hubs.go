// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"net"
	"time"
)

// A Node is the hub's Leadership (see internal/hub): IsLeader,
// LeaderAgentURL and AgentURLs.
//
// Raft only knows each hub's Raft address. The agent-facing URL of each hub
// is replicated next to the rest of the state (store.Hubs): every hub records
// its own with Announce when it starts. A hub whose URL is not recorded yet
// falls back to https://<its raft host>:<Config.AgentPort>, the rule HA-2's
// join redirect already uses.

// LeaderAgentURL is the leader's agent-facing URL, or "" while no leader is
// known.
func (n *Node) LeaderAgentURL() string {
	l := n.Leader()
	if l.ID == "" {
		return ""
	}
	return n.agentURL(n.hubURLs(context.Background()), l.ID, l.Addr)
}

// AgentURLs are the agent-facing URLs of every hub in the Raft configuration,
// in configuration order. Hubs without a known URL are left out.
func (n *Node) AgentURLs() []string {
	if n.raft == nil {
		return nil
	}
	cf := n.raft.GetConfiguration()
	if cf.Error() != nil {
		return nil
	}
	urls := n.hubURLs(context.Background())
	var out []string
	for _, s := range cf.Configuration().Servers {
		if u := n.agentURL(urls, string(s.ID), string(s.Address)); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// hubURLs reads the recorded agent URLs from the local store. On error it
// returns none, so callers fall back to derived URLs.
func (n *Node) hubURLs(ctx context.Context) map[string]string {
	urls, err := n.store.Hubs().AgentURLs(ctx)
	if err != nil {
		n.log.WarnContext(ctx, "read hub URLs", "err", err)
		return nil
	}
	return urls
}

// agentURL is hub id's agent-facing URL: its own config for this hub, else
// the recorded one, else derived from its Raft address and AgentPort.
func (n *Node) agentURL(urls map[string]string, id, raftAddr string) string {
	if id == n.cfg.NodeID && n.cfg.AgentURL != "" {
		return n.cfg.AgentURL
	}
	if u := urls[id]; u != "" {
		return u
	}
	host, _, err := net.SplitHostPort(raftAddr)
	if err != nil || n.cfg.AgentPort == "" {
		return ""
	}
	return "https://" + net.JoinHostPort(host, n.cfg.AgentPort)
}

// announceRetry is how long Announce waits between attempts.
const announceRetry = 2 * time.Second

// Announce records Config.AgentURL as this hub's agent URL in the replicated
// store, through the leader, and retries until it is recorded or ctx ends.
func (n *Node) Announce(ctx context.Context) {
	if n.cfg.AgentURL == "" {
		return
	}
	for {
		urls, err := n.store.Hubs().AgentURLs(ctx)
		if err == nil && urls[n.cfg.NodeID] == n.cfg.AgentURL {
			return
		}
		if err == nil {
			if err = n.store.Hubs().SetAgentURL(ctx, n.cfg.NodeID, n.cfg.AgentURL); err == nil {
				n.log.InfoContext(ctx, "recorded this hub's agent URL in the cluster", "agent_url", n.cfg.AgentURL)
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		n.log.WarnContext(ctx, "cannot record this hub's agent URL yet; retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(announceRetry):
		}
	}
}
