// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

const (
	// logRing is how many of its last lines an active log source keeps, for
	// a stream that joins it later or reads too slowly.
	logRing = 500
	// defaultLogTail is how many of the last lines a stream starts with
	// when the request sets none.
	defaultLogTail = 100
	// maxLogLine caps one line's text; the rest is cut.
	maxLogLine = 4 << 10
	// maxLogRead caps the bytes read for one line of the source's output
	// (a journald JSON record): longer records are cut and shown raw.
	maxLogRead = 64 << 10
)

// Log managers a ceiling entry or a LogRequest may name.
var logManagers = []string{"systemd", "systemd-user", "docker"}

// ParseLogs checks a Ceiling.Logs entry: manager:pattern.
func ParseLogs(entry string) error {
	manager, pattern, ok := strings.Cut(entry, ":")
	if !ok || pattern == "" || !slices.Contains(logManagers, manager) {
		return fmt.Errorf("logs entry %q: want manager:name with manager one of %s", entry, strings.Join(logManagers, ", "))
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("logs entry %q: %w", entry, err)
	}
	return nil
}

// logArgv is the command that follows src, printing its last tail lines
// first. No shell is involved; the name is a flag value or follows "--", so
// it can never be read as a flag.
func logArgv(src *agentv1.LogSource, tail int) []string {
	n := strconv.Itoa(tail)
	switch src.GetManager() {
	case "systemd", "systemd-user":
		// --user-unit matches the agent user's own unit in every journal it
		// may read: its user journal, or the system journal when user
		// journals are not split off (as with volatile storage).
		unit := "--unit="
		if src.GetManager() == "systemd-user" {
			unit = "--user-unit="
		}
		return []string{"journalctl", unit + src.GetName(), "--follow", "--lines=" + n,
			"--output=json", "--output-fields=MESSAGE", "--no-pager", "--quiet"}
	case "docker":
		return []string{"docker", "logs", "--follow", "--timestamps", "--tail", n, "--", src.GetName()}
	}
	return nil
}

// logStreams serves the LogRequests of one hub session. Streams of the same
// source share one process and its ring of last lines; the process stops,
// and the ring is dropped, as soon as its last stream ends. Nothing is kept
// for a source nobody reads.
type logStreams struct {
	ceiling Ceiling
	log     *slog.Logger
	// argv builds the command of a source; logArgv, or a fake in tests.
	argv func(src *agentv1.LogSource, tail int) []string

	// procs are the source goroutines; wait waits for them.
	procs sync.WaitGroup

	mu      sync.Mutex
	sources map[string]*logSource         // by manager:name, active only
	cancels map[string]context.CancelFunc // by request id
}

func newLogStreams(c Ceiling, log *slog.Logger) *logStreams {
	return &logStreams{
		ceiling: c, log: log, argv: logArgv,
		sources: map[string]*logSource{}, cancels: map[string]context.CancelFunc{},
	}
}

// wait waits for every source process to be gone. Call it once every
// stream has returned.
func (l *logStreams) wait() { l.procs.Wait() }

// cancel ends the stream of request id, if it is still open.
func (l *logStreams) cancel(id string) {
	l.mu.Lock()
	cancel := l.cancels[id]
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// stream serves req until ctx is done, the hub cancels it or the source
// ends, sending its lines with send. send blocks until the message is
// handed on or its context is done.
func (l *logStreams) stream(ctx context.Context, req *agentv1.LogRequest,
	send func(context.Context, *agentv1.AgentMessage) bool,
) {
	id := req.GetId()
	msg := func(m *agentv1.LogLines) *agentv1.AgentMessage {
		m.Id = id
		return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_LogLines{LogLines: m}}
	}
	src := req.GetSource()
	if err := l.check(src); err != nil {
		send(ctx, msg(&agentv1.LogLines{End: true, Denied: errors.Is(err, policy.ErrBeyondCeiling), Error: err.Error()}))
		return
	}
	tail := defaultLogTail
	if t := req.GetTail(); t > 0 {
		tail = int(min(t, logRing))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	l.mu.Lock()
	if _, dup := l.cancels[id]; dup {
		l.mu.Unlock()
		send(ctx, msg(&agentv1.LogLines{End: true, Error: "duplicate log request id"}))
		return
	}
	l.cancels[id] = cancel
	s, cursor := l.acquireLocked(src, tail)
	l.mu.Unlock()
	defer l.release(id, s)
	l.log.InfoContext(ctx, "log stream opened", "id", id, "source", s.key)
	defer l.log.InfoContext(ctx, "log stream closed", "id", id, "source", s.key)

	for {
		lines, next, skipped, changed, ended, errText := s.since(cursor)
		cursor = next
		if len(lines) > 0 || skipped > 0 || ended {
			if !send(ctx, msg(&agentv1.LogLines{Lines: lines, Skipped: skipped, End: ended, Error: errText})) || ended {
				return
			}
			continue // more may have come while sending
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
	}
}

// check refuses src unless the ceiling allows it.
func (l *logStreams) check(src *agentv1.LogSource) error {
	if !slices.Contains(logManagers, src.GetManager()) {
		return fmt.Errorf("unknown log manager %q", src.GetManager())
	}
	return policy.LogsWithinCeiling(l.ceiling.proto(), src)
}

// acquireLocked returns the active source of src, starting it if there is
// none, and the cursor a new stream of it starts at: tail lines back.
func (l *logStreams) acquireLocked(src *agentv1.LogSource, tail int) (*logSource, uint64) {
	key := src.GetManager() + ":" + src.GetName()
	if s := l.sources[key]; s != nil && !s.hasEnded() {
		s.refs++
		next := s.head()
		return s, next - min(next, uint64(tail)) //nolint:gosec // tail is small and positive
	}
	ctx, stop := context.WithCancel(context.Background())
	s := &logSource{key: key, refs: 1, stop: stop, changed: make(chan struct{})}
	l.sources[key] = s
	argv := l.argv(src, tail)
	l.procs.Go(func() {
		defer stop()
		s.end(l.run(ctx, src.GetManager(), argv, s))
	})
	return s, 0
}

// release ends stream id's hold on s; the last one stops its process.
func (l *logStreams) release(id string, s *logSource) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.cancels, id)
	s.refs--
	if s.refs > 0 {
		return
	}
	if l.sources[s.key] == s {
		delete(l.sources, s.key)
	}
	s.stop()
}

// run runs argv until ctx is done or it exits, appending each line of its
// output to s. It returns why the source ended; nil when ctx was canceled.
func (l *logStreams) run(ctx context.Context, manager string, argv []string, s *logSource) error {
	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("log pipe: %w", err)
	}
	defer pr.Close()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is built by logArgv, no shell
	cmd.Stdout = pw
	var stderr bytes.Buffer
	if manager == "docker" {
		cmd.Stderr = pw // a container's stderr is part of its log
	} else {
		cmd.Stderr = &limitedBuffer{buf: &stderr, max: stderrTail * 4}
	}
	cmd.WaitDelay = time.Second
	err = cmd.Start()
	_ = pw.Close() // the child holds its own copy
	if err != nil {
		return fmt.Errorf("start %s: %w", argv[0], err)
	}
	parse := parseDockerLine
	if manager != "docker" {
		parse = parseJournalLine
	}
	br := bufio.NewReaderSize(pr, 4<<10)
	for {
		line, rerr := readLogLine(br, maxLogRead)
		if len(line) > 0 {
			s.append(parse(line))
		}
		if rerr != nil {
			break
		}
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	msg := fmt.Sprintf("%s exited", argv[0])
	if err != nil {
		msg = fmt.Sprintf("%s: %v", argv[0], err)
	}
	if tail := lastBytes(stderr.Bytes(), stderrTail); tail != "" {
		msg += ": " + tail
	}
	return errors.New(msg)
}

// readLogLine reads one line without its newline, at most limit bytes of
// it; the rest of a longer line is dropped.
func readLogLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if room := limit - len(line); room > 0 {
			line = append(line, chunk[:min(len(chunk), room)]...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimRight(line, "\r\n"), err
	}
}

// parseJournalLine reads a journalctl --output=json record.
func parseJournalLine(b []byte) *agentv1.LogLine {
	var rec struct {
		TS      string          `json:"__REALTIME_TIMESTAMP"`
		Message json.RawMessage `json:"MESSAGE"`
	}
	if json.Unmarshal(b, &rec) != nil {
		return &agentv1.LogLine{Text: clipLine(string(b))}
	}
	line := &agentv1.LogLine{}
	if us, err := strconv.ParseInt(rec.TS, 10, 64); err == nil {
		line.Ts = timestamppb.New(time.UnixMicro(us))
	}
	// MESSAGE is a string, or an array of bytes when it is not valid UTF-8.
	var text string
	if json.Unmarshal(rec.Message, &text) != nil {
		var raw []byte
		var ints []int
		if json.Unmarshal(rec.Message, &ints) == nil {
			for _, i := range ints {
				raw = append(raw, byte(i)) //nolint:gosec // journald encodes bytes as 0-255
			}
		}
		text = strings.ToValidUTF8(string(raw), "�")
	}
	line.Text = clipLine(text)
	return line
}

// parseDockerLine reads a docker logs --timestamps line: an RFC 3339
// timestamp, a space, the text.
func parseDockerLine(b []byte) *agentv1.LogLine {
	s := strings.ToValidUTF8(string(b), "�")
	if ts, text, ok := strings.Cut(s, " "); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return &agentv1.LogLine{Ts: timestamppb.New(t), Text: clipLine(text)}
		}
	}
	return &agentv1.LogLine{Text: clipLine(s)}
}

// clipLine cuts s to maxLogLine bytes on a rune boundary.
func clipLine(s string) string {
	if len(s) <= maxLogLine {
		return s
	}
	s = s[:maxLogLine]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}

// logSource is one running source and its ring of last lines.
type logSource struct {
	key  string
	stop context.CancelFunc
	// refs is the number of streams reading it; guarded by logStreams.mu.
	refs int

	mu   sync.Mutex
	ring [logRing]*agentv1.LogLine
	// next is the sequence number of the next line; line n is in
	// ring[n%logRing] while n >= next-logRing.
	next uint64
	// changed is closed, and replaced, on every new line and at the end.
	changed chan struct{}
	ended   bool
	err     string
}

func (s *logSource) append(line *agentv1.LogLine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring[s.next%logRing] = line
	s.next++
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *logSource) end(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = true
	if err != nil {
		s.err = err.Error()
	}
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *logSource) hasEnded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ended
}

func (s *logSource) head() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

// since returns the lines from cursor on, the cursor after them, how many
// lines before them the ring no longer holds, a channel closed on the next
// change, and whether (and why) the source ended.
func (s *logSource) since(cursor uint64) (lines []*agentv1.LogLine, next, skipped uint64, changed <-chan struct{}, ended bool, err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next > logRing && cursor < s.next-logRing {
		skipped = s.next - logRing - cursor
		cursor = s.next - logRing
	}
	for n := cursor; n < s.next; n++ {
		lines = append(lines, s.ring[n%logRing])
	}
	// Report the end only with the last lines.
	return lines, s.next, skipped, s.changed, s.ended, s.err
}

// limitedBuffer keeps the first max bytes written to it and drops the rest.
type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
