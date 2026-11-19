// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// TestShellExitKillsJobs leaves a job running and exits the shell: the
// session ends with the shell, not only when the hub closes it.
func TestShellExitKillsJobs(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "job")
	r := newShellRig(t, Ceiling{Shell: true})
	r.send(open())
	if r.next(t).GetStarted() == nil {
		t.Fatal("not started")
	}
	r.input("sleep 300 & echo $! > " + file + "; echo job-$((1+1))\n")
	r.until(t, regexp.MustCompile(`job-2`))
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	job, err := strconv.Atoi(string(bytes.TrimSpace(b)))
	if err != nil {
		t.Fatal(err)
	}
	r.input("exit 0\n")
	if ex := r.exited(t); ex.GetError() != "" {
		t.Errorf("exit = %v, want the shell's own", ex)
	}
	for range 100 {
		if err := syscall.Kill(job, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(job, syscall.SIGKILL)
	t.Errorf("job %d still runs after the shell exited", job)
}

func TestShellInputBoundedInBytes(t *testing.T) {
	t.Parallel()
	sh := newShell("/bin/sh", nil, nil)
	chunk := make([]byte, shellChunk)
	queued := 0
	for sh.enqueue(chunk) {
		queued += len(chunk)
		if queued > shellInputBytes {
			t.Fatalf("queued %d bytes, more than the %d allowed", queued, shellInputBytes)
		}
	}
	if shellInputBytes-queued >= len(chunk) {
		t.Errorf("refused at %d bytes, want it to fill up to %d", queued, shellInputBytes)
	}
	// Small messages are bounded by their number too.
	sh = newShell("/bin/sh", nil, nil)
	n := 0
	for sh.enqueue([]byte("x")) {
		n++
	}
	if n != shellInputQueue {
		t.Errorf("queued %d messages, want %d", n, shellInputQueue)
	}
}

func TestShellCapsSessions(t *testing.T) {
	t.Parallel()
	r := newShellRig(t, Ceiling{Shell: true})
	req := func(id string) *agentv1.ShellRequest {
		o := open()
		o.Id = id
		return o
	}
	for i := range maxShells {
		r.h.handle(r.ctx, req(fmt.Sprintf("s%d", i)))
	}
	for started := 0; started < maxShells; {
		if r.next(t).GetStarted() != nil {
			started++
		}
	}
	r.h.handle(r.ctx, req("over"))
	for {
		ev := r.next(t)
		if ev.GetId() != "over" {
			continue
		}
		if ex := ev.GetExited(); ex == nil || ex.GetError() == "" {
			t.Fatalf("answer = %v, want a refusal", ev)
		}
		break
	}
	r.h.mu.Lock()
	n := len(r.h.shells)
	r.h.mu.Unlock()
	if n != maxShells {
		t.Errorf("%d shells running, want %d", n, maxShells)
	}
}

func TestPollableIsCloseOnExec(t *testing.T) {
	t.Parallel()
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pty here: %v", err)
	}
	defer func() { _ = tty.Close() }()
	f, err := pollable(ptmx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var ferr error
	if err := rc.Control(func(fd uintptr) { flags, ferr = unix.FcntlInt(fd, unix.F_GETFD, 0) }); err != nil {
		t.Fatal(err)
	}
	if ferr != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Errorf("flags = %#x, %v; want close-on-exec", flags, ferr)
	}
}
