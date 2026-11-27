// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// minExecMinor is the first agent protocol minor version that answers
// ExecRequest. Older agents ignore it, so the hub never sends it to them.
const minExecMinor = 1

// minCeilingMinor is the first agent protocol minor version that reports
// its capability ceiling. The hub sends no ExecRequest to an older agent:
// it cannot check one against a ceiling it does not know.
const minCeilingMinor = 2

// minProbeMinor is the first agent protocol minor version that answers
// ProbeRequest and reports whether its ceiling allows probes.
const minProbeMinor = 3

// sendTimeout bounds one send to an agent, waiting for its turn included. A
// send that takes longer has an agent that stopped reading its stream (HTTP/2
// flow control holds the send), and the stream is torn down: the agent
// reconnects, and no caller waits on it for ever.
const sendTimeout = 3 * time.Second

// ErrAgentNotConnected is returned by Agents.Exec for a device whose agent has
// no open stream to this hub.
var ErrAgentNotConnected = errors.New("agent not connected")

// Agents tracks the open agent streams and runs exec requests over them.
// Callers decide through policy first. Agents then refuses any request
// beyond the capability ceiling the device's agent reported, before sending
// it, and the agent enforces its ceiling again.
type Agents struct {
	devices store.Devices
	// sendTimeout is sendTimeout, shorter in tests.
	sendTimeout time.Duration
	// hubsDebounce and hubsRecheck pace RunHubsPush; shorter in tests.
	hubsDebounce, hubsRecheck time.Duration
	// local, when set, pushes local rules and records their runs
	// (localrules.go).
	local atomic.Pointer[LocalRulesConfig]

	mu       sync.Mutex
	sessions map[string]*agentSession

	// masters and routes, in an AP cluster, forward the requests for a
	// device streaming to another master (forward.go).
	masters Masters
	routes  store.DeviceRoutes

	// devicePlugins and blobs, when set, are the plugins uploaded for
	// devices and their programs, handed to the agents (agentplugins.go).
	devicePlugins *store.DevicePlugins
	pluginStore   *store.Store
	blobs         *PluginBlobs
}

// NewAgents returns an Agents that resolves device references in devices.
func NewAgents(devices store.Devices) *Agents {
	return &Agents{
		devices: devices, sendTimeout: sendTimeout, hubsDebounce: hubsDebounce, hubsRecheck: hubsRecheck,
		sessions: map[string]*agentSession{},
	}
}

// agentSession is one open agent stream.
type agentSession struct {
	// device is the id of the stream's device.
	device string
	minor  uint32
	// sendTimeout bounds each send (see sendMsg).
	sendTimeout time.Duration
	// stalled is set once a send outlasted sendTimeout and tore the stream
	// down.
	stalled atomic.Bool
	// sendMu serialises sends: a stream allows one sender at a time. It
	// also guards closed: once the handler is done with the stream, nothing
	// may send on it.
	sendMu sync.Mutex
	send   func(*agentv1.HubMessage) error
	closed bool
	// abort tears the stream down, for an agent that stopped reading it.
	abort func()
	// done is closed when the stream ends.
	done chan struct{}

	mu      sync.Mutex
	pending map[string]chan *agentv1.ExecResult
	probes  map[string]chan *agentv1.ProbeResult
	scans   map[string]chan *agentv1.ScanResult
	dockers map[string]chan *agentv1.DockerResult
	// upgrades wait for UpgradeResults; noUpgrade is why the agent said it
	// does not upgrade itself, if it did.
	upgrades  map[string]chan *agentv1.UpgradeResult
	noUpgrade string
	// logs are the open log streams, by LogRequest id (see agentlogs.go).
	logs   map[string]*logQueue
	shells map[string]*Shell
	// ceiling is the capability ceiling the agent last reported.
	ceiling *agentv1.Ceiling
	// lastNetEdges is when the hub last took the stream's network edges.
	lastNetEdges time.Time
	// ceilingMu serialises CeilingConfig pushes; sentCeiling is the ceiling
	// the agent last got (ceilingpush.go).
	ceilingMu   sync.Mutex
	sentCeiling *agentv1.CeilingConfig
	// hubs is the hub list the agent last got, in Welcome or Hubs.
	hubs []string
	// rules are the local rules the agent last got (localrules.go).
	rules localRulesState
	// pluginRuns wait for PluginResults; pluginStatus is the state of the
	// agent's plugins as it last reported it (agentplugins.go).
	pluginRuns   map[string]chan *agentv1.PluginResult
	pluginStatus *agentv1.PluginStatus
	// pluginMu serialises PluginConfig pushes; sentPlugins is the config
	// the agent last got.
	pluginMu    sync.Mutex
	sentPlugins *agentv1.PluginConfig
}

// attach records the stream of deviceID. A newer stream of the same device
// replaces an older one. Call detach when the stream ends.
func (a *Agents) attach(deviceID string, hello *agentv1.Hello, send func(*agentv1.HubMessage) error, abort func()) *agentSession {
	s := &agentSession{
		device: deviceID, sendTimeout: a.sendTimeout,
		minor: hello.GetProtocolVersion().GetMinor(), send: send, abort: abort, done: make(chan struct{}),
		pending: map[string]chan *agentv1.ExecResult{}, probes: map[string]chan *agentv1.ProbeResult{},
		scans: map[string]chan *agentv1.ScanResult{}, dockers: map[string]chan *agentv1.DockerResult{},
		upgrades: map[string]chan *agentv1.UpgradeResult{}, noUpgrade: hello.GetNoSelfUpgrade(),
		logs: map[string]*logQueue{}, shells: map[string]*Shell{}, ceiling: hello.GetCeiling(),
		pluginRuns: map[string]chan *agentv1.PluginResult{},
	}
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
	s.endShells()
}

// setCeiling records the ceiling an agent reported in its facts.
func (s *agentSession) setCeiling(c *agentv1.Ceiling) {
	s.mu.Lock()
	s.ceiling = c
	s.mu.Unlock()
}

// check refuses req unless the agent reported a ceiling that allows it.
func (s *agentSession) check(device string, req *agentv1.ExecRequest) error {
	if s.minor < minExecMinor {
		return fmt.Errorf("device %s: agent is too old to run actions; upgrade it", device)
	}
	if s.minor < minCeilingMinor {
		return fmt.Errorf("device %s: agent is too old to report its capability ceiling; upgrade it: %w",
			device, policy.ErrBeyondCeiling)
	}
	s.mu.Lock()
	c := s.ceiling
	s.mu.Unlock()
	if err := policy.WithinCeiling(c, req); err != nil {
		return fmt.Errorf("device %s: %w", device, err)
	}
	return nil
}

// checkProbe refuses a probe unless the agent reported a ceiling that
// allows probes.
func (s *agentSession) checkProbe(device string) error {
	if s.minor < minProbeMinor {
		return fmt.Errorf("device %s: agent is too old to run checks; upgrade it: %w", device, policy.ErrBeyondCeiling)
	}
	s.mu.Lock()
	c := s.ceiling
	s.mu.Unlock()
	if err := policy.ProbeWithinCeiling(c); err != nil {
		return fmt.Errorf("device %s: %w (turn Checks on in its Capabilities)", device, err)
	}
	return nil
}

// deliverProbe hands a probe result to the request waiting for it, as
// deliver does.
func (s *agentSession) deliverProbe(r *agentv1.ProbeResult) {
	s.mu.Lock()
	ch := s.probes[r.GetId()]
	delete(s.probes, r.GetId())
	s.mu.Unlock()
	if ch != nil {
		ch <- r
	}
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

// session returns the open stream of device (a device id, name or
// hostname).
func (a *Agents) session(ctx context.Context, device string) (*agentSession, error) {
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
	return s, nil
}

// Check reports whether req would be sent to the agent of device: it fails
// with an error wrapping policy.ErrBeyondCeiling when req is beyond the
// ceiling the agent reported, and with ErrAgentNotConnected when the agent
// has no open stream to this hub.
func (a *Agents) Check(ctx context.Context, device string, req *agentv1.ExecRequest) error {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		_, err := a.call(ctx, master, "exec", agentCall{Device: id, CheckOnly: true}, req, nil)
		return err
	}
	if err != nil {
		return err
	}
	return s.check(device, req)
}

// Exec sends req to the agent of device (a device id, name or hostname) and
// waits for its result, until ctx is done or the stream ends. It sets req's
// id. A request beyond the ceiling the agent reported is never sent: Exec
// fails with an error wrapping policy.ErrBeyondCeiling. The result may still
// be a refusal (Denied) or a failure (Error); otherwise Exec only fails when
// the request could not be delivered or answered.
func (a *Agents) Exec(ctx context.Context, device string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		res := &agentv1.ExecResult{}
		if _, err := a.call(ctx, master, "exec", agentCall{Device: id}, req, res); err != nil {
			return nil, err
		}
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.check(device, req); err != nil {
		return nil, err
	}

	req.Id = strings.ToLower(rand.Text())
	return roundTrip(ctx, s, device, s.pending, req.Id,
		&agentv1.HubMessage{Payload: &agentv1.HubMessage_ExecRequest{ExecRequest: req}})
}

// CheckProbe reports whether a probe would be sent to the agent of device:
// it fails with an error wrapping policy.ErrBeyondCeiling when the agent is
// too old for probes or its reported ceiling does not allow them, and with
// ErrAgentNotConnected when the agent has no open stream to this hub.
func (a *Agents) CheckProbe(ctx context.Context, device string) error {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		_, err := a.call(ctx, master, "probe", agentCall{Device: id, CheckOnly: true}, nil, nil)
		return err
	}
	if err != nil {
		return err
	}
	return s.checkProbe(device)
}

// Probe sends req to the agent of device and waits for its result, as Exec
// does. A probe the agent's reported ceiling does not allow is never sent:
// Probe fails with an error wrapping policy.ErrBeyondCeiling.
func (a *Agents) Probe(ctx context.Context, device string, req *agentv1.ProbeRequest) (*agentv1.ProbeResult, error) {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		res := &agentv1.ProbeResult{}
		if _, err := a.call(ctx, master, "probe", agentCall{Device: id}, req, res); err != nil {
			return nil, err
		}
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.checkProbe(device); err != nil {
		return nil, err
	}
	req.Id = strings.ToLower(rand.Text())
	return roundTrip(ctx, s, device, s.probes, req.Id,
		&agentv1.HubMessage{Payload: &agentv1.HubMessage_ProbeRequest{ProbeRequest: req}})
}

// roundTrip sends msg, a request of this id, on s and waits for its result
// in pending, until ctx is done or the stream ends.
func roundTrip[R any](ctx context.Context, s *agentSession, device string, pending map[string]chan R, id string,
	msg *agentv1.HubMessage,
) (R, error) {
	var zero R
	ch := make(chan R, 1)
	s.mu.Lock()
	pending[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(pending, id)
		s.mu.Unlock()
	}()

	if err := s.sendMsg(msg); err != nil {
		return zero, fmt.Errorf("send request to device %s: %w", device, err)
	}
	select {
	case r := <-ch:
		return r, nil
	case <-s.done:
		return zero, fmt.Errorf("device %s: agent disconnected before answering: %w", device, automation.ErrOutcomeUnknown)
	case <-ctx.Done():
		return zero, fmt.Errorf("device %s: %w", device, context.Cause(ctx))
	}
}

// sendMsg sends msg on the stream, the one way anything is sent to an agent.
// It returns within s.sendTimeout or so: a send that takes longer, waiting
// for its turn included, tears the stream down, which ends the send that
// blocks it, and fails with an error saying the agent is not reading.
func (s *agentSession) sendMsg(msg *agentv1.HubMessage) error {
	timer := time.AfterFunc(s.sendTimeout, func() {
		s.stalled.Store(true)
		s.abort()
	})
	s.sendMu.Lock()
	err := ErrAgentNotConnected
	if !s.closed {
		err = s.send(msg)
	}
	s.sendMu.Unlock()
	timer.Stop()
	if err != nil && s.stalled.Load() {
		return fmt.Errorf("agent %s is not reading: its stream was torn down after a send took over %s: %w",
			s.device, s.sendTimeout, ErrAgentNotConnected)
	}
	return err
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
