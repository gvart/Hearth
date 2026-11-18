// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
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

// subscribeEvents subscribes to h's registry until the test ends.
func subscribeEvents(t *testing.T, h *testHub) <-chan hub.Event {
	t.Helper()
	events, unsubscribe := h.reg.Subscribe()
	t.Cleanup(unsubscribe)
	return events
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
	// Count device.offline on every hub from subscriptions of this test's
	// own, opened once each hub has caught up: restoring the bootstrap
	// snapshot ends earlier subscriptions (Registry.Restored).
	offline := map[*testHub]*atomic.Int32{}
	for _, h := range hubs {
		ctx, cancel := context.WithTimeout(t.Context(), waitFor)
		err := h.WaitReady(ctx)
		cancel()
		if err != nil {
			t.Fatalf("%s catching up: %v", h.ID(), err)
		}
		n, events := &atomic.Int32{}, subscribeEvents(t, h)
		offline[h] = n
		go func() {
			for e := range events {
				if e.Type == hub.EventDeviceOffline {
					if e.Device.ID != "pi" {
						t.Errorf("%s: device.offline for %s", h.ID(), e.Device.ID)
					}
					n.Add(1)
				}
			}
		}()
	}

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
	// The leader publishes from its own call, followers from the applied
	// MarkDevicesOffline: exactly one device.offline, for pi, on every hub.
	for _, h := range hubs {
		eventually(t, "device.offline on "+h.ID(), func() bool { return offline[h].Load() > 0 })
	}
	time.Sleep(3 * every) // room for a duplicate to show up
	for _, h := range hubs {
		if n := offline[h].Load(); n != 1 {
			t.Errorf("%s published device.offline %d times, want once", h.ID(), n)
		}
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
