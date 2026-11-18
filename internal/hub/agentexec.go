// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// minExecMinor is the first agent protocol minor version that answers
// ExecRequest. Older agents ignore it, so the hub never sends it to them.
const minExecMinor = 1

// ErrAgentNotConnected is returned by Agents.Exec for a device whose agent has
// no open stream to this hub.
var ErrAgentNotConnected = errors.New("agent not connected")

// Agents tracks the open agent streams and runs exec requests over them. It is
// a transport only: callers decide through policy first, and the agent
// enforces its own capability ceiling.
type Agents struct {
	devices store.Devices

	mu       sync.Mutex
	sessions map[string]*agentSession
}

// NewAgents returns an Agents that resolves device references in devices.
func NewAgents(devices store.Devices) *Agents {
	return &Agents{devices: devices, sessions: map[string]*agentSession{}}
}

// agentSession is one open agent stream.
type agentSession struct {
	minor uint32
	// sendMu serialises sends: a stream allows one sender at a time. It
	// also guards closed: once the handler is done with the stream, nothing
	// may send on it.
	sendMu sync.Mutex
	send   func(*agentv1.HubMessage) error
	closed bool
	// done is closed when the stream ends.
	done chan struct{}

	mu      sync.Mutex
	pending map[string]chan *agentv1.ExecResult
}

// attach records the stream of deviceID. A newer stream of the same device
// replaces an older one. Call detach when the stream ends.
func (a *Agents) attach(deviceID string, minor uint32, send func(*agentv1.HubMessage) error) *agentSession {
	s := &agentSession{minor: minor, send: send, done: make(chan struct{}), pending: map[string]chan *agentv1.ExecResult{}}
	a.mu.Lock()
	a.sessions[deviceID] = s
	a.mu.Unlock()
	return s
}

// detach forgets s, if it is still the stream of deviceID, and fails the
// requests waiting on it.
func (a *Agents) detach(deviceID string, s *agentSession) {
	a.mu.Lock()
	if a.sessions[deviceID] == s {
		delete(a.sessions, deviceID)
	}
	a.mu.Unlock()
	s.sendMu.Lock()
	s.closed = true
	s.sendMu.Unlock()
	close(s.done)
}

// deliver hands a result to the request waiting for it; a result nobody
// waits for (its request timed out) is dropped.
func (s *agentSession) deliver(r *agentv1.ExecResult) {
	s.mu.Lock()
	ch := s.pending[r.GetId()]
	delete(s.pending, r.GetId())
	s.mu.Unlock()
	if ch != nil {
		ch <- r // buffered; each id is delivered at most once
	}
}

// Exec sends req to the agent of device (a device id, name or hostname) and
// waits for its result, until ctx is done or the stream ends. It sets req's
// id. The result may be a refusal (Denied) or a failure (Error): Exec only
// fails when the request could not be delivered or answered.
func (a *Agents) Exec(ctx context.Context, device string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	id, err := a.resolve(ctx, device)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	s := a.sessions[id]
	a.mu.Unlock()
	if s == nil {
		return nil, fmt.Errorf("device %s: %w", device, ErrAgentNotConnected)
	}
	if s.minor < minExecMinor {
		return nil, fmt.Errorf("device %s: agent is too old to run actions; upgrade it", device)
	}

	req.Id = strings.ToLower(rand.Text())
	ch := make(chan *agentv1.ExecResult, 1)
	s.mu.Lock()
	s.pending[req.Id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, req.Id)
		s.mu.Unlock()
	}()

	s.sendMu.Lock()
	if s.closed {
		err = ErrAgentNotConnected
	} else {
		err = s.send(&agentv1.HubMessage{Payload: &agentv1.HubMessage_ExecRequest{ExecRequest: req}})
	}
	s.sendMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send request to device %s: %w", device, err)
	}
	select {
	case r := <-ch:
		return r, nil
	case <-s.done:
		return nil, fmt.Errorf("device %s: agent disconnected before answering", device)
	case <-ctx.Done():
		return nil, fmt.Errorf("device %s: %w", device, context.Cause(ctx))
	}
}

// resolve returns the id of the device named by ref: its id, or else its
// name or hostname when exactly one device has it.
func (a *Agents) resolve(ctx context.Context, ref string) (string, error) {
	devs, err := a.devices.List(ctx)
	if err != nil {
		return "", fmt.Errorf("resolve device %s: %w", ref, err)
	}
	var match []string
	for _, d := range devs {
		if d.ID == ref {
			return d.ID, nil
		}
		if d.Name == ref || d.Hostname == ref {
			match = append(match, d.ID)
		}
	}
	switch len(match) {
	case 0:
		return "", fmt.Errorf("device %s: %w", ref, store.ErrNotFound)
	case 1:
		return match[0], nil
	}
	return "", fmt.Errorf("device %s is ambiguous: %d devices have that name or hostname; use the device id", ref, len(match))
}
