// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// ShellSupported reports whether this agent can run interactive shells.
const ShellSupported = true

// startShell starts the user's login shell, or argv when set (in tests), on
// a new PTY of size, in a session (and process group) of its own, in the
// home directory.
func startShell(size *agentv1.TerminalSize, argv []string) (*shell, error) {
	if len(argv) == 0 {
		argv = []string{shellPath(), "-l"}
	}
	path := argv[0]
	cmd := exec.Command(path, argv[1:]...)
	cmd.Env = shellEnv(os.Environ())
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	} else {
		cmd.Dir = "/"
	}
	ptmx, err := pty.StartWithSize(cmd, winsize(size))
	if err != nil {
		return nil, fmt.Errorf("start %s on a pty: %w", path, err)
	}
	f, err := pollable(ptmx)
	if err != nil {
		killSession(cmd.Process.Pid)
		_ = cmd.Wait()
		return nil, err
	}
	return newShell(path, cmd, f), nil
}

// pollable returns a non-blocking duplicate of the PTY master and closes
// the original. Go's poller then serves it, so closing it ends a pending
// Read or Write on every platform: on macOS a blocking PTY read would wait
// for as long as any process keeps the terminal open.
func pollable(f *os.File) (*os.File, error) {
	defer func() { _ = f.Close() }()
	var dup int
	var err error
	rc, cerr := f.SyscallConn()
	if cerr != nil {
		return nil, fmt.Errorf("pty: %w", cerr)
	}
	if cerr := rc.Control(func(fd uintptr) {
		// Atomically close-on-exec: a child started meanwhile must not
		// inherit the terminal.
		dup, err = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	}); cerr != nil {
		return nil, fmt.Errorf("pty: %w", cerr)
	}
	if err != nil {
		return nil, fmt.Errorf("dup pty: %w", err)
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		_ = unix.Close(dup)
		return nil, fmt.Errorf("pty non-blocking: %w", err)
	}
	return os.NewFile(uintptr(dup), "/dev/ptmx"), nil
}

// resize sets the PTY's window size. It does not use pty.Setsize, whose
// File.Fd call would make the PTY blocking again.
func (sh *shell) resize(size *agentv1.TerminalSize) error {
	rc, err := sh.pty.SyscallConn()
	if err != nil {
		return err
	}
	ws := winsize(size)
	var ierr error
	if err := rc.Control(func(fd uintptr) {
		ierr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: ws.Rows, Col: ws.Cols})
	}); err != nil {
		return err
	}
	return ierr
}

// winsize is size within what a terminal can be, 80x24 when unset.
func winsize(size *agentv1.TerminalSize) *pty.Winsize {
	clamp := func(v uint32, def uint16) uint16 {
		if v == 0 {
			return def
		}
		return uint16(min(v, 1000))
	}
	return &pty.Winsize{Rows: clamp(size.GetRows(), 24), Cols: clamp(size.GetCols(), 80)}
}

// shellPath is the user's shell: $SHELL, else bash, else sh.
func shellPath() string {
	if s := os.Getenv("SHELL"); filepath.IsAbs(s) {
		if fi, err := os.Stat(s); err == nil && !fi.IsDir() { //nolint:gosec // the agent's own $SHELL
			return s
		}
	}
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}

// shellEnv is the agent's environment for a shell: without HEARTH_*
// variables, which may carry the agent's secrets, and with a TERM the web
// terminal understands.
func shellEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "HEARTH_") || strings.HasPrefix(kv, "TERM=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "TERM=xterm-256color")
}

// hangupSession sends SIGHUP to the session the shell sid leads, as a
// terminal that goes away does: the shell's process group and every other
// process of the session, foreground and background jobs included.
func hangupSession(sid int) { signalSession(sid, syscall.SIGHUP) }

// killSession kills every process of the session sid. It does not rely on
// SIGHUP, which an agent started under nohup passes on ignored.
func killSession(sid int) { signalSession(sid, syscall.SIGKILL) }

func signalSession(sid int, sig syscall.Signal) {
	if sid <= 1 {
		return
	}
	_ = syscall.Kill(-sid, sig)
	for _, pid := range processes() {
		if pid == sid || pid <= 1 {
			continue
		}
		if s, err := unix.Getsid(pid); err == nil && s == sid {
			_ = syscall.Kill(pid, sig)
		}
	}
}
