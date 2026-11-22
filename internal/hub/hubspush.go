// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"slices"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// An agent learns the masters from its Welcome. A master that appears
// later, or one that goes, reaches the agents already streaming by a Hubs
// message, so an agent whose hub stops knows where else to go (#328).

// hubsDebounce is how long the masters must stay unchanged before the new
// hub list is pushed, so a flapping member pushes once.
const hubsDebounce = 2 * time.Second

// hubsRecheck is how often the hub list is re-read without a change of the
// masters: a new master's URL is recorded (and replicated) after it joins
// the ring.
const hubsRecheck = 30 * time.Second

// RunHubsPush pushes the hub list hubs returns to every open stream until
// ctx ends: once the masters, signalled on changed, have been still for a
// moment, and every so often in case the URLs arrived late. A stream is
// sent a list only when it differs from the last one it got, its Welcome's
// included.
func (a *Agents) RunHubsPush(ctx context.Context, hubs func() []string, changed <-chan struct{}) error {
	recheck := time.NewTicker(a.hubsRecheck)
	defer recheck.Stop()
	debounce := time.NewTimer(a.hubsDebounce)
	debounce.Stop()
	defer debounce.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			debounce.Reset(a.hubsDebounce)
			continue
		case <-debounce.C:
		case <-recheck.C:
		}
		a.PushHubs(hubs())
	}
}

// PushHubs sends urls in a Hubs message to every open stream whose agent
// last got another list. An empty list is never sent: agents keep theirs.
func (a *Agents) PushHubs(urls []string) {
	if len(urls) == 0 {
		return
	}
	a.mu.Lock()
	sessions := make([]*agentSession, 0, len(a.sessions))
	for _, s := range a.sessions {
		sessions = append(sessions, s)
	}
	a.mu.Unlock()
	msg := &agentv1.HubMessage{Payload: &agentv1.HubMessage_Hubs{Hubs: &agentv1.Hubs{Urls: urls}}}
	for _, s := range sessions {
		if slices.Equal(s.sentHubs(), urls) {
			continue
		}
		// A failed send ends the stream (sendMsg): the agent reconnects
		// and its Welcome carries the list.
		if s.sendMsg(msg) == nil {
			s.setHubs(urls)
		}
	}
}

// sentHubs is the hub list the stream's agent last got.
func (s *agentSession) sentHubs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hubs
}

// setHubs records urls as the hub list the stream's agent last got.
func (s *agentSession) setHubs(urls []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hubs = slices.Clone(urls)
}
