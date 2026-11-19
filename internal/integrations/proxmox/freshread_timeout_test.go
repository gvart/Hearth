// SPDX-License-Identifier: AGPL-3.0-only

package proxmox

import (
	"errors"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// The read that confirms a guest gets as long as a poll does: a server slow
// enough to show as connected must not fail every action.
func TestFreshReadUsesThePollTimeout(t *testing.T) {
	m := NewManager(Config{})
	if m.readTimeout != requestTimeout {
		t.Errorf("readTimeout = %v, want requestTimeout %v", m.readTimeout, requestTimeout)
	}
}

// A server that answers the fresh read slower than a short limit but within
// the limit still gets the action; one slower than the limit is given up on
// and nothing is sent to it.
func TestActionWaitsForASlowFreshRead(t *testing.T) {
	for name, tc := range map[string]struct {
		delay time.Duration
		want  error
		posts int
	}{
		"within the limit": {150 * time.Millisecond, nil, 1},
		"beyond the limit": {time.Second, ErrUnavailable, 0},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPolledFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{
				policy.Safe: policy.ModeAllow, policy.Dangerous: policy.ModeAllow,
			}}, noPoll)
			info := f.add(t)
			f.m.readTimeout = 500 * time.Millisecond
			f.mock.SetDelay(tc.delay)
			_, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, info.ID, ActionRequest{Action: ActionStop, VMID: 100})
			if !errors.Is(err, tc.want) {
				t.Errorf("Act = %v, want %v", err, tc.want)
			}
			if n := len(f.mock.Posts()); n != tc.posts {
				t.Errorf("POSTs = %d, want %d", n, tc.posts)
			}
		})
	}
}
