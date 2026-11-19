// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestParseLogs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		entry string
		ok    bool
	}{
		{"systemd:nginx.service", true},
		{"systemd:*", true},
		{"systemd-user:hearth-*", true},
		{"docker:*", true},
		{"docker", false},
		{"docker:", false},
		{"podman:web", false},
		{"systemd:[", false},
	} {
		if err := ParseLogs(tc.entry); (err == nil) != tc.ok {
			t.Errorf("ParseLogs(%q) = %v, want ok=%v", tc.entry, err, tc.ok)
		}
	}
}

func TestLogArgv(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		src  *agentv1.LogSource
		want []string
	}{
		{
			&agentv1.LogSource{Manager: "systemd", Name: "-x.service"},
			[]string{"journalctl", "--unit=-x.service", "--follow", "--lines=5", "--output=export", "--output-fields=MESSAGE", "--no-pager", "--quiet"},
		},
		{
			&agentv1.LogSource{Manager: "systemd-user", Name: "a.service"},
			[]string{"journalctl", "--user-unit=a.service", "--follow", "--lines=5", "--output=export", "--output-fields=MESSAGE", "--no-pager", "--quiet"},
		},
		{
			&agentv1.LogSource{Manager: "docker", Name: "--privileged"},
			[]string{"docker", "logs", "--follow", "--timestamps", "--tail", "5", "--", "--privileged"},
		},
		{&agentv1.LogSource{Manager: "podman", Name: "x"}, nil},
	} {
		if got := logArgv(tc.src, 5); !slices.Equal(got, tc.want) {
			t.Errorf("logArgv(%v) = %q, want %q", tc.src, got, tc.want)
		}
	}
}

// exportLen is the length before a binary field's value in journalctl
// --output=export.
func exportLen(n uint64) string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return string(b[:])
}

// exportBinary is a binary field of journalctl --output=export.
func exportBinary(key, value string) string {
	return key + "\n" + exportLen(uint64(len(value))) + value + "\n"
}

func TestReadJournalEntry(t *testing.T) {
	t.Parallel()
	const cursor = "__CURSOR=s=1;i=2\n__REALTIME_TIMESTAMP=1700000000123456\n__MONOTONIC_TIMESTAMP=9\n_BOOT_ID=b\n"
	type entry struct {
		text string
		ts   bool
	}
	for _, tc := range []struct {
		name string
		in   string
		want []entry
	}{
		{"text", cursor + "MESSAGE=hello\n\n", []entry{{"hello", true}}},
		{"two entries", cursor + "MESSAGE=a\n\n" + cursor + "MESSAGE=b=c\n\n", []entry{{"a", true}, {"b=c", true}}},
		{"several lines", cursor + exportBinary("MESSAGE", "one\ntwo") + "\n", []entry{{"one\ntwo", true}}},
		{"not UTF-8", cursor + exportBinary("MESSAGE", "hi\xff") + "\n", []entry{{"hi�", true}}},
		{"no message", cursor + "\n", []entry{{"", true}}},
		{"no timestamp", "MESSAGE=x\n\n", []entry{{"x", false}}},
		{"cut short", cursor + "MESSAGE=last", []entry{{"last", true}}},
		{"binary cut short", cursor + "MESSAGE\n" + exportLen(9) + "abc", []entry{{"", true}}},
		{"binary length cut short", cursor + "MESSAGE\n\x09\x00", []entry{{"", true}}},
		{"binary without newline", "MESSAGE\n" + exportLen(2) + "hi" + "_PID=1\n\nMESSAGE=next\n\n", []entry{{"hi", false}, {"next", false}}},
		{"binary over the field cap", cursor + "MESSAGE\n" + exportLen(1<<62) + "abc", []entry{{"", true}}},
		{"blank lines between entries", "\n\nMESSAGE=a\n\n\n\nMESSAGE=b\n\n", []entry{{"a", false}, {"b", false}}},
		{"empty", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := bufio.NewReader(strings.NewReader(tc.in))
			var got []entry
			for {
				line, err := readJournalEntry(r, maxLogRead)
				if line != nil {
					got = append(got, entry{line.GetText(), line.GetTs() != nil})
				}
				if err != nil {
					break
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("entries = %+v, want %+v", got, tc.want)
			}
		})
	}
	line, _ := readJournalEntry(bufio.NewReader(strings.NewReader(cursor+"MESSAGE=x\n\n")), maxLogRead)
	if want := time.UnixMicro(1700000000123456); !line.GetTs().AsTime().Equal(want) {
		t.Errorf("ts = %v, want %v", line.GetTs().AsTime(), want)
	}
}

// TestReadJournalEntryLimit: a field longer than the limit (a binary value,
// or a text line with its key) is cut, and the entries after it are still
// read.
func TestReadJournalEntryLimit(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 100)
	in := exportBinary("MESSAGE", long) + "\n" + "MESSAGE=" + long + "\n\nMESSAGE=after\n\n"
	r := bufio.NewReader(strings.NewReader(in))
	for _, want := range []string{long[:20], long[:20-len("MESSAGE=")], "after"} {
		line, err := readJournalEntry(r, 20)
		if line.GetText() != want {
			t.Fatalf("text = %q (err %v), want %q", line.GetText(), err, want)
		}
	}
}

// TestReadJournalEntryCorrupt: a binary field longer than journald allows
// ends the output with an error rather than reading on to find its end.
func TestReadJournalEntryCorrupt(t *testing.T) {
	t.Parallel()
	r := bufio.NewReader(strings.NewReader("MESSAGE\n" + exportLen(maxJournalField+1) + "MESSAGE=x\n\n"))
	if _, err := readJournalEntry(r, maxLogRead); !errors.Is(err, errJournalCorrupt) {
		t.Fatalf("err = %v, want %v", err, errJournalCorrupt)
	}
}

// FuzzDecodeExport feeds readJournalEntry arbitrary output, read through a
// small buffer and with a small limit so that long lines and fields are
// cut: it never panics, always makes progress, and every line it returns
// is valid UTF-8 within maxLogLine.
func FuzzDecodeExport(f *testing.F) {
	const cursor = "__CURSOR=s=1\n__REALTIME_TIMESTAMP=1700000000123456\n"
	for _, seed := range []string{
		"",
		"\n\n",
		cursor + "MESSAGE=hello\n\n",
		cursor + "MESSAGE=a\n\n" + cursor + "MESSAGE=b=c\n\n",
		cursor + exportBinary("MESSAGE", "one\ntwo") + "\n",
		cursor + exportBinary("MESSAGE", "hi\xff\xfe") + "\n",
		"MESSAGE\n" + exportLen(2) + "hiX=1\n\n",
		"MESSAGE\n" + exportLen(1<<62) + "abc",
		"MESSAGE\n" + exportLen(100) + strings.Repeat("y", 100) + "\n\n",
		"MESSAGE=" + strings.Repeat("z", 300) + "\n\n",
		"__REALTIME_TIMESTAMP=-1\nMESSAGE\n\x01",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReaderSize(bytes.NewReader(data), 16)
		for range len(data) + 2 {
			line, err := readJournalEntry(r, 64)
			if text := line.GetText(); !utf8.ValidString(text) || len(text) > maxLogLine+len("…") {
				t.Fatalf("text %q: not valid UTF-8 or too long", text)
			}
			if err != nil {
				return
			}
		}
		t.Fatalf("no end after %d entries of %d bytes", len(data)+2, len(data))
	})
}

func TestParseDockerLine(t *testing.T) {
	t.Parallel()
	got := parseDockerLine([]byte("2024-05-01T10:00:00.123456789Z GET / 200"))
	if got.GetText() != "GET / 200" || got.GetTs().AsTime().Nanosecond() != 123456789 {
		t.Errorf("parseDockerLine = %v", got)
	}
	if got := parseDockerLine([]byte("no timestamp here")); got.GetText() != "no timestamp here" || got.GetTs() != nil {
		t.Errorf("parseDockerLine without timestamp = %v", got)
	}
}

func TestReadLogLineCutsLongLines(t *testing.T) {
	t.Parallel()
	in := strings.Repeat("a", 10000) + "\nshort\n"
	r := bufio.NewReaderSize(strings.NewReader(in), 16)
	line, err := readLogLine(r, 100)
	if err != nil || len(line) != 100 {
		t.Fatalf("first line: %d bytes, %v; want 100", len(line), err)
	}
	if line, err := readLogLine(r, 100); err != nil || string(line) != "short" {
		t.Fatalf("second line = %q, %v", line, err)
	}
	if got := clipLine(strings.Repeat("é", maxLogLine)); len(got) > maxLogLine+len("…") || !strings.HasSuffix(got, "…") {
		t.Errorf("clipLine kept %d bytes", len(got))
	}
}

func TestLogSourceRing(t *testing.T) {
	t.Parallel()
	s := &logSource{changed: make(chan struct{})}
	for i := range logRing + 10 {
		s.append(&agentv1.LogLine{Text: strings.Repeat("x", i%3)})
	}
	lines, next, skipped, _, ended, _ := s.since(0)
	if len(lines) != logBatch || next != 10+logBatch || skipped != 10 || ended {
		t.Errorf("since(0) = %d lines, next %d, skipped %d, ended %v", len(lines), next, skipped, ended)
	}
	s.end(nil)
	if _, _, _, _, ended, _ := s.since(next); ended {
		t.Error("since reports the end before the last lines")
	}
	next = s.head()
	lines, _, skipped, _, _, _ = s.since(next - 3)
	if len(lines) != 3 || skipped != 0 {
		t.Errorf("since(next-3) = %d lines, skipped %d", len(lines), skipped)
	}
}

// fakeLogs is a logStreams whose sources are a shell loop printing a
// numbered docker-style line every few milliseconds, counting the
// processes it starts.
func fakeLogs(t *testing.T, ceiling Ceiling, script string) (*logStreams, *atomic.Int32) {
	l, started, _ := fakeLogsFreed(t, ceiling, script)
	return l, started
}

// fakeLogsFreed is fakeLogs that also counts how often memory is freed.
func fakeLogsFreed(t *testing.T, ceiling Ceiling, script string) (*logStreams, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	l := newLogStreams(ceiling, slog.New(slog.DiscardHandler))
	var started atomic.Int32
	l.argv = func(*agentv1.LogSource, int) []string {
		started.Add(1)
		return []string{"/bin/sh", "-c", script}
	}
	var freed atomic.Int32
	l.freeMemory = func() { freed.Add(1) }
	return l, &started, &freed
}

const loopScript = `i=0; while :; do echo "2024-05-01T10:00:00Z line $i"; i=$((i+1)); sleep 0.01; done`

// logCollector receives what a stream sends.
type logCollector struct {
	mu   sync.Mutex
	msgs []*agentv1.LogLines
}

func (c *logCollector) send(_ context.Context, m *agentv1.AgentMessage) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m.GetLogLines())
	return true
}

func (c *logCollector) lines() (n int, last *agentv1.LogLines) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.msgs {
		n += len(m.GetLines())
		last = m
	}
	return n, last
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLogStreamDeniedBeyondCeiling(t *testing.T) {
	t.Parallel()
	l, started := fakeLogs(t, Ceiling{Logs: []string{"docker:web"}}, loopScript)
	for _, src := range []*agentv1.LogSource{
		{Manager: "docker", Name: "db"},
		{Manager: "systemd", Name: "web"},
		{Manager: "podman", Name: "web"},
		{Manager: "docker", Name: ""},
	} {
		var c logCollector
		l.stream(t.Context(), &agentv1.LogRequest{Id: "1", Source: src}, c.send)
		_, last := c.lines()
		if last == nil || !last.GetEnd() || last.GetError() == "" {
			t.Errorf("stream of %v sent %v, want an end with an error", src, last)
		}
	}
	var c logCollector
	l.stream(t.Context(), &agentv1.LogRequest{Id: "2", Source: &agentv1.LogSource{Manager: "docker", Name: "db"}}, c.send)
	if _, last := c.lines(); !last.GetDenied() {
		t.Errorf("beyond the ceiling: %v, want denied", last)
	}
	if n := started.Load(); n != 0 {
		t.Errorf("%d processes started for refused streams", n)
	}
	// The zero ceiling allows nothing.
	l, _ = fakeLogs(t, Ceiling{}, loopScript)
	c = logCollector{}
	l.stream(t.Context(), &agentv1.LogRequest{Id: "3", Source: &agentv1.LogSource{Manager: "docker", Name: "web"}}, c.send)
	if _, last := c.lines(); !last.GetDenied() {
		t.Errorf("zero ceiling: %v, want denied", last)
	}
}

// TestLogStreamsShareAndStop opens two streams of one source: they share
// one process, a late one starts with the last lines, and once both are
// canceled the process and every goroutine are gone.
func TestLogStreamsShareAndStop(t *testing.T) {
	before := runtime.NumGoroutine()
	l, started, freed := fakeLogsFreed(t, Ceiling{Logs: []string{"docker:*"}}, loopScript)
	src := &agentv1.LogSource{Manager: "docker", Name: "web"}
	var streams sync.WaitGroup
	var a, b logCollector
	streams.Go(func() { l.stream(t.Context(), &agentv1.LogRequest{Id: "a", Source: src}, a.send) })
	eventually(t, "first lines", func() bool { n, _ := a.lines(); return n >= 10 })
	streams.Go(func() { l.stream(t.Context(), &agentv1.LogRequest{Id: "b", Source: src, Tail: 5}, b.send) })
	eventually(t, "late stream lines", func() bool { n, _ := b.lines(); return n >= 7 })
	if n := started.Load(); n != 1 {
		t.Errorf("%d processes for one source, want 1", n)
	}
	b.mu.Lock()
	first := b.msgs[0].GetLines()
	b.mu.Unlock()
	if len(first) > 6 {
		t.Errorf("late stream started with %d lines, want about its tail of 5", len(first))
	}
	if !strings.HasPrefix(first[0].GetText(), "line ") || first[0].GetTs() == nil {
		t.Errorf("line = %v, want parsed docker line", first[0])
	}

	l.cancel("a")
	l.cancel("b")
	streams.Wait()
	l.wait()
	if len(l.sources) != 0 || len(l.cancels) != 0 {
		t.Errorf("after cancel: %d sources, %d streams kept", len(l.sources), len(l.cancels))
	}
	if n := freed.Load(); n != 1 {
		t.Errorf("memory freed %d times once the source stopped, want 1", n)
	}
	// A new stream starts a new process.
	var c logCollector
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); l.stream(ctx, &agentv1.LogRequest{Id: "c", Source: src}, c.send) }()
	eventually(t, "lines after restart", func() bool { n, _ := c.lines(); return n > 0 })
	cancel() // as when the session ends
	<-done
	l.wait()
	if n := started.Load(); n != 2 {
		t.Errorf("%d processes, want 2", n)
	}
	eventually(t, "goroutines to end", func() bool { return runtime.NumGoroutine() <= before })
}

func TestLogStreamSourceEnds(t *testing.T) {
	t.Parallel()
	l, _ := fakeLogs(t, Ceiling{Logs: []string{"systemd:*"}}, `printf 'MESSAGE=bye\\n\\n'; echo 'No journal files were found.' >&2; exit 1`)
	var c logCollector
	l.stream(t.Context(), &agentv1.LogRequest{Id: "1", Source: &agentv1.LogSource{Manager: "systemd", Name: "x.service"}}, c.send)
	l.wait()
	n, last := c.lines()
	if n != 1 || !last.GetEnd() || !strings.Contains(last.GetError(), "No journal files") {
		t.Errorf("got %d lines, last %v; want the line, then an end with stderr", n, last)
	}
}
