// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// shellRig is a shellHost whose replies go to events.
type shellRig struct {
	h      *shellHost
	events chan *agentv1.ShellEvent
	wg     *sync.WaitGroup
	ctx    context.Context
}

func newShellRig(t *testing.T, c Ceiling) *shellRig {
	t.Helper()
	r := &shellRig{events: make(chan *agentv1.ShellEvent, 1024), wg: &sync.WaitGroup{}, ctx: t.Context()}
	r.h = newShellHost(c, slog.New(slog.DiscardHandler), r.wg, func(m *agentv1.AgentMessage) {
		r.events <- m.GetShellEvent()
	})
	// A login shell reads the user's profile, which may take long on a
	// busy host; the real one is tested over the stream.
	r.h.argv = []string{"/bin/sh"}
	t.Cleanup(func() {
		r.h.closeAll()
		r.wg.Wait()
	})
	return r
}

func (r *shellRig) send(req *agentv1.ShellRequest) {
	req.Id = "s1"
	r.h.handle(r.ctx, req)
}

// next is the next event, or fails after a while.
func (r *shellRig) next(t *testing.T) *agentv1.ShellEvent {
	t.Helper()
	select {
	case ev := <-r.events:
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("no shell event")
		return nil
	}
}

// until reads output until it matches re, acknowledging it; it returns the
// output read and the first non-output event, if any came.
func (r *shellRig) until(t *testing.T, re *regexp.Regexp) []byte {
	t.Helper()
	var out []byte
	for !re.Match(out) {
		ev := r.next(t)
		o := ev.GetOutput()
		if o == nil {
			t.Fatalf("event %v while waiting for %s in %q", ev, re, out)
		}
		out = append(out, o...)
		r.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Ack{Ack: uint32(len(o))}}) //nolint:gosec // small
	}
	return out
}

func (r *shellRig) input(s string) {
	r.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Input{Input: []byte(s)}})
}

// exited skips output up to the session's end.
func (r *shellRig) exited(t *testing.T) *agentv1.ShellExited {
	t.Helper()
	for {
		if ex := r.next(t).GetExited(); ex != nil {
			return ex
		}
	}
}

func open() *agentv1.ShellRequest {
	return &agentv1.ShellRequest{Op: &agentv1.ShellRequest_Open{Open: &agentv1.ShellOpen{
		Size: &agentv1.TerminalSize{Rows: 30, Cols: 100},
	}}}
}

// TestShellDeniedBeyondCeiling is the device's own ceiling: the agent gets
// a ShellRequest the hub should never have sent (its check bypassed) and
// refuses it without starting anything.
func TestShellDeniedBeyondCeiling(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]Ceiling{
		"zero ceiling":       {},
		"everything but":     {Exec: []string{"/bin/sh", "/bin/bash"}, Restart: []string{"systemd:x"}, Probe: true},
		"exec of the shells": {Exec: []string{shellPath()}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newShellRig(t, c)
			r.send(open())
			ev := r.next(t)
			ex := ev.GetExited()
			if ex == nil || !ex.GetDenied() || ex.GetExitCode() != -1 || ev.GetId() != "s1" {
				t.Fatalf("answer = %v, want a denial", ev)
			}
			if !regexp.MustCompile(regexp.QuoteMeta(policy.ErrBeyondCeiling.Error())).MatchString(ex.GetError()) {
				t.Errorf("error = %q, want beyond the ceiling", ex.GetError())
			}
			r.h.mu.Lock()
			n := len(r.h.shells)
			r.h.mu.Unlock()
			if n != 0 {
				t.Errorf("%d shells running after a denial", n)
			}
			// Input for the refused session goes nowhere.
			r.input("touch /tmp/never\n")
			select {
			case ev := <-r.events:
				t.Errorf("event after a denial: %v", ev)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

func TestShellSession(t *testing.T) {
	t.Parallel()
	r := newShellRig(t, Ceiling{Shell: true})
	r.send(open())
	started := r.next(t).GetStarted()
	if started == nil || started.GetShell() == "" {
		t.Fatalf("first event %v, want started", started)
	}
	r.input("echo out-$((6*7)); stty size\n")
	if out := r.until(t, regexp.MustCompile(`out-42\r?\n30 100`)); !bytes.Contains(out, []byte("out-42")) {
		t.Fatalf("output %q", out)
	}
	r.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Resize{Resize: &agentv1.TerminalSize{Rows: 50, Cols: 132}}})
	r.input("stty size\n")
	r.until(t, regexp.MustCompile(`50 132`))
	r.input("exit 3\n")
	if ex := r.exited(t); ex.GetExitCode() != 3 || ex.GetError() != "" || ex.GetDenied() {
		t.Fatalf("exit = %v, want status 3", ex)
	}
}

// TestShellCloseKillsSession closes a session with a job in the background
// that keeps the terminal open and one in the foreground, each in a process
// group of its own and ignoring SIGHUP (as everything does under an agent
// started with nohup): the session still ends promptly, and every process
// of it with it.
func TestShellCloseKillsSession(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bgFile, fgFile := filepath.Join(dir, "bg"), filepath.Join(dir, "fg")
	r := newShellRig(t, Ceiling{Shell: true})
	r.send(open())
	if r.next(t).GetStarted() == nil {
		t.Fatal("not started")
	}
	r.input("trap '' HUP; sleep 300 & echo $! > " + bgFile + "; echo bg-$((1+1))\n")
	r.until(t, regexp.MustCompile(`bg-2`))
	r.input("sh -c 'echo $$ > " + fgFile + "; exec sleep 301'\n")
	readPID := func(file string) int {
		t.Helper()
		for range 500 { // 10s: a login shell can be slow to start on a busy host
			b, err := os.ReadFile(file)
			if pid, perr := strconv.Atoi(string(bytes.TrimSpace(b))); err == nil && perr == nil {
				return pid
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("no pid in %s", file)
		return 0
	}
	bg, fg := readPID(bgFile), readPID(fgFile)
	r.h.mu.Lock()
	shellPID := r.h.shells["s1"].cmd.Process.Pid
	r.h.mu.Unlock()

	start := time.Now()
	r.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Close{Close: &agentv1.ShellClose{}}})
	ex := r.exited(t)
	if ex.GetError() != "session closed" {
		t.Errorf("exit = %v, want session closed", ex)
	}
	if d := time.Since(start); d > shellKillGrace+shellDrain+2*time.Second {
		t.Errorf("close took %s", d)
	}
	for _, pid := range []int{shellPID, bg, fg} {
		gone := false
		for range 100 {
			if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
				gone = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !gone {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Errorf("process %d still runs after the session closed", pid)
		}
	}
}

func TestShellEndsWithStream(t *testing.T) {
	t.Parallel()
	r := newShellRig(t, Ceiling{Shell: true})
	r.send(open())
	if r.next(t).GetStarted() == nil {
		t.Fatal("not started")
	}
	r.h.closeAll() // the stream ended
	if ex := r.exited(t); ex.GetError() != "session closed" {
		t.Errorf("exit = %v", ex)
	}
}

func TestShellEnv(t *testing.T) {
	t.Parallel()
	got := shellEnv([]string{"PATH=/bin", "HEARTH_DATA_DIR=/x", "TERM=dumb", "HOME=/h"})
	want := []string{"PATH=/bin", "HOME=/h", "TERM=xterm-256color"}
	if len(got) != len(want) {
		t.Fatalf("shellEnv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("shellEnv = %v, want %v", got, want)
		}
	}
}
