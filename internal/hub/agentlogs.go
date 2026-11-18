// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// minLogsMinor is the first agent protocol minor version that streams logs
// and reports which sources its ceiling allows.
const minLogsMinor = 4

// logBuffer is how many LogLines messages of one stream the hub holds for a
// slow reader before it ends the stream.
const logBuffer = 64

// ErrLogReaderTooSlow ends a log stream whose reader fell too far behind.
var ErrLogReaderTooSlow = errors.New("log stream ended: the reader fell too far behind")

// checkLogs refuses src unless the agent reported a ceiling that allows it.
func (s *agentSession) checkLogs(device string, src *agentv1.LogSource) error {
	if s.minor < minLogsMinor {
		return fmt.Errorf("device %s: agent is too old to stream logs; upgrade it: %w", device, policy.ErrBeyondCeiling)
	}
	s.mu.Lock()
	c := s.ceiling
	s.mu.Unlock()
	if err := policy.LogsWithinCeiling(c, src); err != nil {
		return fmt.Errorf("device %s: %w (start its agent with --allow-logs)", device, err)
	}
	return nil
}

// deliverLogs hands lines to the stream of their id. It never blocks the
// agent's stream: a reader that fell logBuffer messages behind loses its
// stream, and the agent is told to stop it. The channel is closed after the
// last message, or at once for a reader too slow.
func (s *agentSession) deliverLogs(m *agentv1.LogLines) {
	id := m.GetId()
	s.mu.Lock()
	ch := s.logs[id]
	if ch == nil {
		s.mu.Unlock()
		return
	}
	full := false
	select {
	case ch <- m:
	default:
		full = true
	}
	if full || m.GetEnd() {
		delete(s.logs, id)
		close(ch)
	}
	s.mu.Unlock()
	if full {
		s.sendNoWait(&agentv1.HubMessage{Payload: &agentv1.HubMessage_LogCancel{LogCancel: &agentv1.LogCancel{Id: id}}})
	}
}

// sendNoWait sends msg unless the stream is closed; a failure only means
// the stream is ending.
func (s *agentSession) sendNoWait(msg *agentv1.HubMessage) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if !s.closed {
		_ = s.send(msg)
	}
}

// LogStream is an open stream of a device's log source.
type LogStream struct {
	s    *agentSession
	id   string
	ch   chan *agentv1.LogLines
	once sync.Once
}

// Lines delivers the stream's messages from the agent. It is closed after
// the last one, which has End set, or early, without one, when the reader
// fell too far behind (ErrLogReaderTooSlow).
func (l *LogStream) Lines() <-chan *agentv1.LogLines { return l.ch }

// Disconnected is closed when the agent's stream to the hub ends, which
// ends the log stream too.
func (l *LogStream) Disconnected() <-chan struct{} { return l.s.done }

// Close ends the stream and tells the agent to stop it.
func (l *LogStream) Close() {
	l.once.Do(func() {
		l.s.mu.Lock()
		_, open := l.s.logs[l.id]
		delete(l.s.logs, l.id)
		l.s.mu.Unlock()
		if open {
			l.s.sendNoWait(&agentv1.HubMessage{Payload: &agentv1.HubMessage_LogCancel{LogCancel: &agentv1.LogCancel{Id: l.id}}})
		}
	})
}

// CheckLogs reports whether a log stream of src would be opened on the
// agent of device: it fails with an error wrapping policy.ErrBeyondCeiling
// when the agent is too old to stream logs or its reported ceiling does not
// allow src, and with ErrAgentNotConnected when the agent has no open
// stream to this hub.
func (a *Agents) CheckLogs(ctx context.Context, device string, src *agentv1.LogSource) error {
	s, err := a.session(ctx, device)
	if err != nil {
		return err
	}
	return s.checkLogs(device, src)
}

// Logs asks the agent of device to stream src, starting with its last tail
// lines. A source beyond the ceiling the agent reported is never asked
// for: Logs fails with an error wrapping policy.ErrBeyondCeiling. The
// caller decides through policy first and must Close the stream.
func (a *Agents) Logs(ctx context.Context, device string, src *agentv1.LogSource, tail uint32) (*LogStream, error) {
	s, err := a.session(ctx, device)
	if err != nil {
		return nil, err
	}
	if err := s.checkLogs(device, src); err != nil {
		return nil, err
	}
	l := &LogStream{s: s, id: strings.ToLower(rand.Text()), ch: make(chan *agentv1.LogLines, logBuffer)}
	s.mu.Lock()
	s.logs[l.id] = l.ch
	s.mu.Unlock()
	req := &agentv1.HubMessage{Payload: &agentv1.HubMessage_LogRequest{LogRequest: &agentv1.LogRequest{
		Id: l.id, Source: src, Tail: tail,
	}}}
	s.sendMu.Lock()
	if s.closed {
		err = ErrAgentNotConnected
	} else {
		err = s.send(req)
	}
	s.sendMu.Unlock()
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("send log request to device %s: %w", device, err)
	}
	return l, nil
}
