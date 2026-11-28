// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestParseLogsEventLog(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		entry string
		ok    bool
	}{
		{"eventlog:Application", true},
		{"eventlog:System", true},
		{"eventlog:*", true},
		{"eventlog:Microsoft-Windows-Sysmon/Operational", true},
		{"eventlog:", false},
		{"eventlog", false},
		{"winevent:System", false},
	} {
		if err := ParseLogs(tc.entry); (err == nil) != tc.ok {
			t.Errorf("ParseLogs(%q) = %v, want ok=%v", tc.entry, err, tc.ok)
		}
	}
}

func TestValidEventChannel(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"Application", true},
		{"Microsoft-Windows-PowerShell/Operational", true},
		{"Windows PowerShell", true},
		{"", false},
		{strings.Repeat("a", maxEventChannel+1), false},
		{"System\x00", false},
		{"Sys\ntem", false},
		{`C:\Windows\x.evtx`, false},
		{`"System"`, false},
		{"<QueryList>", false},
	} {
		if got := validEventChannel(tc.name); got != tc.ok {
			t.Errorf("validEventChannel(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

const sampleEvent = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>` +
	`<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/>` +
	`<EventID Qualifiers='49152'>7031</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode>` +
	`<Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-11-28T10:00:01.1234567Z'/>` +
	`<EventRecordID>4242</EventRecordID><Correlation/><Execution ProcessID='700' ThreadID='800'/>` +
	`<Channel>System</Channel><Computer>pc</Computer><Security/></System>` +
	`<EventData><Data Name='param1'>Print Spooler</Data><Data Name='param2'>1</Data><Data Name='param3'></Data></EventData></Event>`

func TestEventLine(t *testing.T) {
	t.Parallel()
	ev, err := parseEvent([]byte(sampleEvent))
	if err != nil {
		t.Fatal(err)
	}
	if ev.System.EventRecordID != 4242 {
		t.Errorf("record id = %d, want 4242", ev.System.EventRecordID)
	}
	line := ev.line("The Print Spooler service terminated unexpectedly.\r\nIt has done this 1 time(s).\r\n")
	want := "Error Service Control Manager 7031: The Print Spooler service terminated unexpectedly.\nIt has done this 1 time(s)."
	if line.GetText() != want {
		t.Errorf("text = %q, want %q", line.GetText(), want)
	}
	if got := line.GetTs().AsTime(); !got.Equal(time.Date(2026, 11, 28, 10, 0, 1, 123456700, time.UTC)) {
		t.Errorf("ts = %v", got)
	}

	// No message: the event's data.
	if got := ev.line("").GetText(); got != "Error Service Control Manager 7031: (no message) Print Spooler; 1" {
		t.Errorf("no message: %q", got)
	}

	// UserData, an unknown level, no time; and a long message is cut.
	ev, err = parseEvent([]byte(`<Event><System><Provider Name='X'/><EventID>1</EventID><Level>9</Level></System>` +
		`<UserData><Thing>v</Thing></UserData></Event>`))
	if err != nil {
		t.Fatal(err)
	}
	if got := ev.line(""); got.GetText() != "Level 9 X 1: (no message) <Thing>v</Thing>" || got.GetTs() != nil {
		t.Errorf("userdata: %v", got)
	}
	if got := ev.line(strings.Repeat("é", maxLogLine)).GetText(); len(got) > maxLogLine+len("…") || !strings.HasSuffix(got, "…") {
		t.Errorf("long message: %d bytes", len(got))
	}

	if _, err := parseEvent([]byte("<Event><System>")); err == nil {
		t.Error("truncated XML parsed")
	}
}

// TestEventLogStream streams an event log channel through a fake reader:
// the ceiling is checked first, the tail is passed on, lines arrive, and
// the reader's context ends with the stream.
func TestEventLogStream(t *testing.T) {
	t.Parallel()
	l := newLogStreams(Ceiling{Logs: []string{"eventlog:Application"}}, slog.New(slog.DiscardHandler))
	l.freeMemory = func() {}
	var calls atomic.Int32
	var gotTail atomic.Int32
	l.eventLog = func(ctx context.Context, channel string, tail int, add func(*agentv1.LogLine)) error {
		calls.Add(1)
		gotTail.Store(int32(tail)) //nolint:gosec // small
		add(&agentv1.LogLine{Text: "Information " + channel + " 1: hello"})
		<-ctx.Done()
		return ctx.Err()
	}

	// Beyond the ceiling: denied, the reader never runs.
	for _, src := range []*agentv1.LogSource{
		{Manager: "eventlog", Name: "System"},
		{Manager: "eventlog", Name: "Security"},
		{Manager: "systemd", Name: "Application"},
	} {
		var c logCollector
		l.stream(t.Context(), &agentv1.LogRequest{Id: "d", Source: src}, c.send)
		if _, last := c.lines(); !last.GetDenied() {
			t.Errorf("%v: %v, want denied", src, last)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("reader ran %d times for refused streams", n)
	}

	ctx, cancel := context.WithCancel(t.Context())
	var c logCollector
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.stream(ctx, &agentv1.LogRequest{Id: "1", Tail: 7, Source: &agentv1.LogSource{Manager: "eventlog", Name: "Application"}}, c.send)
	}()
	eventually(t, "a line", func() bool { n, _ := c.lines(); return n == 1 })
	if got := gotTail.Load(); got != 7 {
		t.Errorf("tail = %d, want 7", got)
	}
	cancel()
	<-done
	l.wait()
	if _, last := c.lines(); last.GetError() != "" {
		t.Errorf("canceled stream ended with %q", last.GetError())
	}
}

// TestEventLogEndsWithError: a reader that fails ends the stream with its
// error, as off Windows, where there is no event log.
func TestEventLogEndsWithError(t *testing.T) {
	t.Parallel()
	l := newLogStreams(Ceiling{Logs: []string{"eventlog:*"}}, slog.New(slog.DiscardHandler))
	l.freeMemory = func() {}
	if runtime.GOOS == "windows" {
		l.eventLog = func(context.Context, string, int, func(*agentv1.LogLine)) error {
			return context.DeadlineExceeded
		}
	}
	var c logCollector
	l.stream(t.Context(), &agentv1.LogRequest{Id: "1", Source: &agentv1.LogSource{Manager: "eventlog", Name: "System"}}, c.send)
	l.wait()
	_, last := c.lines()
	if !last.GetEnd() || last.GetError() == "" || last.GetDenied() {
		t.Errorf("got %v, want an end with an error, not denied", last)
	}
	if runtime.GOOS != "windows" && !strings.Contains(last.GetError(), "Windows only") {
		t.Errorf("error %q, want Windows only", last.GetError())
	}
}
