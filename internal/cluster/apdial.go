// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// replicaDialTimeout bounds dialing a member for replication.
const replicaDialTimeout = 5 * time.Second

// DialReplica opens a replication connection (gossipReplica) to the live
// member id, over the gossip port's mutual TLS: the member must present the
// hub node certificate of id.
func (m *Membership) DialReplica(ctx context.Context, id string) (net.Conn, error) {
	return m.dialKind(ctx, id, gossipReplica, "replica")
}

// DialMaster opens a connection to the live member id for HTTP between
// masters (gossipMaster), over the gossip port's mutual TLS: the member must
// present the hub node certificate of id.
func (m *Membership) DialMaster(ctx context.Context, id string) (net.Conn, error) {
	return m.dialKind(ctx, id, gossipMaster, "master")
}

func (m *Membership) dialKind(ctx context.Context, id string, kind byte, what string) (net.Conn, error) {
	t := m.trans.Load()
	if t == nil {
		return nil, errors.New(what + ": membership not started")
	}
	m.mu.Lock()
	l, ok := m.live[id]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s: %s is not a live member", what, id)
	}
	timeout := replicaDialTimeout
	if d, ok := ctx.Deadline(); ok && time.Until(d) < timeout {
		timeout = max(time.Until(d), time.Millisecond)
	}
	c, err := t.stream.Dial(l.info.Address, timeout)
	if err != nil {
		return nil, fmt.Errorf("%s: dial %s: %w", what, id, err)
	}
	if got := peerID(c); got != id {
		_ = c.Close()
		return nil, fmt.Errorf("%s: %s answered with the certificate of %q", what, id, got)
	}
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{kind}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("%s: dial %s: %w", what, id, err)
	}
	_ = c.SetWriteDeadline(time.Time{})
	return c, nil
}
