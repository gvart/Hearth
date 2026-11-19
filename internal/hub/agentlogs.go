// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// minLogsMinor is the first agent protocol minor version that streams logs
// and reports which sources its ceiling allows.
const minLogsMinor = 5

const (
	// logQueueLines is how many lines of one stream the hub holds for its
	// reader. It counts lines, not messages, because an agent sends a tail in
	// as many small messages as its source happens to write; it holds a whole
	// tail (an agent keeps at most 500 lines) with room for new ones.
	logQueueLines = 2048
	// logEventLines caps the lines of one event to the reader.
	logEventLines = 256
)

// logQueue holds the lines of one stream until its reader takes them. The
// reader starts late, once the stream's audit entry is written, and may fall
// behind, and the agent's stream must not wait for it. Past logQueueLines the
// oldest lines go, and the message after them says how many.
type logQueue struct {
	// ready has a value when there may be messages to take.
	ready chan struct{}

	mu    sync.Mutex
	msgs  []*agentv1.LogLines
	lines int
}

func newLogQueue() *logQueue { return &logQueue{ready: make(chan struct{}, 1)} }

// put adds m, dropping the oldest messages over logQueueLines. It never
// blocks and never drops m itself, so the end of a stream always arrives.
func (q *logQueue) put(m *agentv1.LogLines) {
	q.mu.Lock()
	q.msgs = append(q.msgs, m)
	q.lines += len(m.GetLines())
	for q.lines > logQueueLines && len(q.msgs) > 1 {
		old := q.msgs[0]
		q.msgs[0] = nil
		q.msgs = q.msgs[1:]
		q.lines -= len(old.GetLines())
		q.msgs[0].Skipped += old.GetSkipped() + uint64(len(old.GetLines()))
	}
	q.mu.Unlock()
	q.wake()
}

func (q *logQueue) wake() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// take returns the oldest messages joined into one of at most logEventLines
// lines, or nil if there are none. Lines after a gap start a message of their
// own, so that Skipped says where the gap is.
func (q *logQueue) take() *agentv1.LogLines {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.msgs) == 0 {
		return nil
	}
	out := q.msgs[0]
	n := 1
	for n < len(q.msgs) && !out.GetEnd() {
		m := q.msgs[n]
		if m.GetSkipped() > 0 || len(out.GetLines())+len(m.GetLines()) > logEventLines {
			break
		}
		out.Lines = append(out.Lines, m.GetLines()...)
		out.End, out.Error = m.GetEnd(), m.GetError()
		n++
	}
	clear(q.msgs[:n])
	q.msgs = q.msgs[n:]
	q.lines -= len(out.GetLines())
	if len(q.msgs) == 0 {
		q.msgs = nil
	} else {
		q.wake()
	}
	return out
}

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
// agent's stream: a reader too far behind loses its oldest lines and is told
// how many (see logQueue).
func (s *agentSession) deliverLogs(m *agentv1.LogLines) {
	id := m.GetId()
	s.mu.Lock()
	q := s.logs[id]
	if q != nil && m.GetEnd() {
		delete(s.logs, id)
	}
	s.mu.Unlock()
	if q != nil {
		q.put(m)
	}
}

// sendNoWait sends msg unless the stream is closed; a failure only means
// the stream is ending.
func (s *agentSession) sendNoWait(msg *agentv1.HubMessage) {
	_ = s.sendMsg(msg)
}

// LogStream is an open stream of a device's log source.
type LogStream struct {
	s    *agentSession
	id   string
	q    *logQueue
	once sync.Once
}

// Ready has a value when Take may return a message.
func (l *LogStream) Ready() <-chan struct{} { return l.q.ready }

// Take returns the stream's next message from the agent, or nil if there is
// none yet. The last one has End set. Skipped counts the lines lost before a
// message, by the agent or here, because the reader fell behind.
func (l *LogStream) Take() *agentv1.LogLines { return l.q.take() }

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
	l := &LogStream{s: s, id: strings.ToLower(rand.Text()), q: newLogQueue()}
	s.mu.Lock()
	s.logs[l.id] = l.q
	s.mu.Unlock()
	req := &agentv1.HubMessage{Payload: &agentv1.HubMessage_LogRequest{LogRequest: &agentv1.LogRequest{
		Id: l.id, Source: src, Tail: tail,
	}}}
	if err = s.sendMsg(req); err != nil {
		l.Close()
		return nil, fmt.Errorf("send log request to device %s: %w", device, err)
	}
	return l, nil
}
