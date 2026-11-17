// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/hub"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// revokedDetail reports whether err carries the CertificateRevoked detail.
func revokedDetail(err error) bool {
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeUnauthenticated {
		return false
	}
	for _, d := range ce.Details() {
		if v, err := d.Value(); err == nil {
			if _, ok := v.(*agentv1.CertificateRevoked); ok {
				return true
			}
		}
	}
	return false
}

// A `hearth device revoke` on a cluster goes through a hub's control socket
// and Raft. The leader ends the device's live stream at its next heartbeat
// and marks it offline; another device on the same leader keeps streaming.
func TestRevokeThroughControlSocketEndsLiveStream(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	follower := followers(hubs, leader)[0]
	const every = 200 * time.Millisecond // the agents' heartbeat interval
	pi := runTestAgent(t, hubs, "pi", enrollTestDevice(t, leader, "pi"), every, 50*time.Millisecond)
	nas := runTestAgent(t, hubs, "nas", enrollTestDevice(t, leader, "nas"), every, 50*time.Millisecond)
	for _, a := range []*testAgent{pi, nas} {
		eventually(t, "both agents on the leader", func() bool { return a.url() == leader.url })
	}
	eventually(t, "both online", func() bool { return statusOn(leader, "pi") == "online" && statusOn(leader, "nas") == "online" })
	nasWelcomes := nas.welcomes.Load()

	cc := serveControl(t, follower.testNode)
	cli, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "cli.db"), store.WithApplier(func(*store.Store) store.Applier { return cc }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	revokedAt := time.Now()
	if n, err := cli.Certs().RevokeDevice(t.Context(), "pi", time.Now()); err != nil || n != 1 {
		t.Fatalf("revoke through the follower's socket = %d, %v", n, err)
	}

	eventually(t, "pi's stream ended as revoked", func() bool { return revokedDetail(pi.err()) })
	// One heartbeat, plus Raft commit and -race headroom.
	if took := time.Since(revokedAt); took > every+time.Second {
		t.Errorf("stream ended %v after the revoke, want within one heartbeat (%v) plus headroom", took, every)
	}
	for _, h := range hubs {
		eventually(t, "pi offline on "+h.ID(), func() bool { return statusOn(h, "pi") == "offline" })
	}
	if n := len(leader.eventsOf(hub.EventDeviceOffline)); n != 1 {
		t.Errorf("leader published %d device.offline events, want 1 (pi)", n)
	}

	// The other device is untouched: same stream, still heartbeating.
	time.Sleep(3 * every)
	if nas.url() != leader.url || nas.welcomes.Load() != nasWelcomes {
		t.Errorf("nas was disconnected (on %q, %d welcomes, had %d)", nas.url(), nas.welcomes.Load(), nasWelcomes)
	}
	if got := statusOn(leader, "nas"); got != "online" {
		t.Errorf("nas status = %s, want online", got)
	}
	if pi.url() != "" {
		t.Errorf("revoked pi reconnected to %s", pi.url())
	}
}
