// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"os"
	"path/filepath"
	"time"
)

// Files and directories inside a hub data dir.
const (
	// StateDir holds every piece of a member's cluster state: its node ID,
	// node certificate, gossip seeds and written schema.
	StateDir     = "cluster"
	nodeIDFile   = "node-id"
	nodeCertFile = "node.crt"
	nodeKeyFile  = "node.key"
)

// DefaultPort is the default port of --cluster-listen: gossip and
// replication between members, both over mutual TLS.
const DefaultPort = "7444"

// announceRetry is how long a member waits before it tries again to record
// its agent URL.
const announceRetry = 2 * time.Second

// IsMember reports whether dataDir belongs to a cluster member, that is,
// whether a hub ran from it: every hub is a member, of a cluster of one at
// least.
func IsMember(dataDir string) bool {
	info, err := os.Stat(filepath.Join(dataDir, StateDir))
	return err == nil && info.IsDir()
}

// Status is a member's view of the cluster.
type Status struct {
	NodeID string `json:"node_id"`
	// Members are the gossip members this member sees, itself included.
	Members []MemberInfo `json:"members,omitempty"`
	// StorageMembers counts the storage members, Replicas is N, and
	// HighlyAvailable says whether a member can fail without data loss.
	StorageMembers  int  `json:"storage_members"`
	Replicas        int  `json:"replicas"`
	HighlyAvailable bool `json:"highly_available"`
	// SafeToStop says whether this member can stop now without the cluster
	// losing a row or its last master (safestop.go); nil when not asked.
	SafeToStop *SafeStop `json:"safe_to_stop,omitempty"`
}

// Alone reports whether this member is a cluster of one: no other member,
// alive or down, that has not left.
func (s Status) Alone() bool {
	for _, m := range s.Members {
		if m.ID != s.NodeID && m.State != MemberLeft {
			return false
		}
	}
	return true
}
