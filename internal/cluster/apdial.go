// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/raft"
)

// replicaDialTimeout bounds dialing a member for replication.
const replicaDialTimeout = 5 * time.Second

// DialReplica opens a replication connection (gossipReplica) to the live
// member id, over the gossip port's mutual TLS: the member must present the
// hub node certificate of id.
func (m *Membership) DialReplica(ctx context.Context, id string) (net.Conn, error) {
	t := m.trans.Load()
	if t == nil {
		return nil, errors.New("replica: membership not started")
	}
	m.mu.Lock()
	l, ok := m.live[id]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("replica: %s is not a live member", id)
	}
	timeout := replicaDialTimeout
	if d, ok := ctx.Deadline(); ok && time.Until(d) < timeout {
		timeout = max(time.Until(d), time.Millisecond)
	}
	c, err := t.stream.Dial(raft.ServerAddress(l.info.Address), timeout)
	if err != nil {
		return nil, fmt.Errorf("replica: dial %s: %w", id, err)
	}
	if got := peerID(c); got != id {
		_ = c.Close()
		return nil, fmt.Errorf("replica: %s answered with the certificate of %q", id, got)
	}
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{gossipReplica}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("replica: dial %s: %w", id, err)
	}
	_ = c.SetWriteDeadline(time.Time{})
	return c, nil
}
