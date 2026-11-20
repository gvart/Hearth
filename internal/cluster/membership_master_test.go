// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// TestMembershipBroadcastAndLastContact: a broadcast reaches the other
// member's Message callback over the gossip; LastContact advances while a
// peer answers and stops once it is gone.
func TestMembershipBroadcastAndLastContact(t *testing.T) {
	ca := newTestCA(t)
	var (
		mu  sync.Mutex
		got [][]byte
	)
	a := newTestMember(t, ca, "a", memberOpts{})
	aAddr, _ := runMember(t, a)
	b := newTestMember(t, ca, "b", memberOpts{seeds: []string{aAddr}, message: func(m []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, bytes.Clone(m))
	}})
	_, stopB := runMember(t, b)
	both := map[string]string{"a": MemberAlive, "b": MemberAlive}
	waitUntil(t, 10*time.Second, "a and b to see each other", sees(a, both))

	a.Broadcast([]byte("revoked"))
	waitUntil(t, 5*time.Second, "b to get a's broadcast", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, m := range got {
			if string(m) == "revoked" {
				return true
			}
		}
		return false
	})

	first := a.LastContact()
	waitUntil(t, 5*time.Second, "a's last contact to advance", func() bool { return a.LastContact().After(first) })

	stopB()
	waitUntil(t, 10*time.Second, "a to see b gone", func() bool { return states(a)["b"] != MemberAlive })
	time.Sleep(300 * time.Millisecond) // packets in flight
	stalled := a.LastContact()
	time.Sleep(time.Second)
	if a.LastContact().After(stalled) {
		t.Errorf("a's last contact advanced with no peer: %v after %v", a.LastContact(), stalled)
	}
}
