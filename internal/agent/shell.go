// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

const (
	// shellWindow is how many output bytes may be unacknowledged before the
	// agent stops reading the PTY: the hub acknowledges what it delivered,
	// so a slow browser slows the shell instead of filling memory.
	shellWindow = 256 << 10
	// shellChunk is the largest output message.
	shellChunk = 32 << 10
	// shellInputQueue is how many input messages may wait for the PTY. A
	// shell that reads none of them for this long has its session ended.
	shellInputQueue = 256
	// shellKillGrace is how long a closed shell has between SIGHUP and
	// SIGKILL.
	shellKillGrace = 2 * time.Second
	// shellDrain is how long output may still be read once the shell exited.
	shellDrain = time.Second
)

// shellHost runs the shell sessions of one hub stream. Its goroutines are
// in wg; closeAll ends every session when the stream ends.
type shellHost struct {
	ceiling Ceiling
	log     *slog.Logger
	// reply sends a message to the hub, in order for one goroutine; it
	// returns once the message is sent or the stream ends.
	reply func(*agentv1.AgentMessage)
	wg    *sync.WaitGroup

	mu     sync.Mutex
	shells map[string]*shell
	// argv is the shell to start instead of the user's login shell: tests
	// set it to one that starts fast.
	argv []string
}

func newShellHost(c Ceiling, log *slog.Logger, wg *sync.WaitGroup, reply func(*agentv1.AgentMessage)) *shellHost {
	return &shellHost{ceiling: c, log: log, reply: reply, wg: wg, shells: map[string]*shell{}}
}

// shell is one running shell on a PTY.
type shell struct {
	path string
	cmd  *exec.Cmd
	pty  *os.File
	in   chan []byte
	// exited is closed once the shell exited.
	exited chan struct{}

	mu      sync.Mutex
	unacked int
	killed  bool
	kill    *time.Timer
	// acked wakes a reader waiting for the window.
	acked chan struct{}
}

// handle carries out one request from the hub. It never blocks on a shell.
func (h *shellHost) handle(ctx context.Context, req *agentv1.ShellRequest) {
	id := req.GetId()
	if id == "" {
		return
	}
	if open := req.GetOpen(); open != nil {
		h.open(ctx, id, open)
		return
	}
	h.mu.Lock()
	sh := h.shells[id]
	h.mu.Unlock()
	if sh == nil {
		return // ended already
	}
	switch op := req.GetOp().(type) {
	case *agentv1.ShellRequest_Input:
		select {
		case sh.in <- op.Input:
		default:
			h.log.WarnContext(ctx, "shell input overflow; ending the session", "id", id)
			sh.close()
		}
	case *agentv1.ShellRequest_Resize:
		if err := sh.resize(op.Resize); err != nil {
			h.log.DebugContext(ctx, "resize shell", "id", id, "err", err)
		}
	case *agentv1.ShellRequest_Ack:
		sh.ack(int(op.Ack))
	case *agentv1.ShellRequest_Close:
		sh.close()
	}
}

// open starts a shell if the ceiling allows it. The hub checks the same
// before it asks; the agent never relies on that.
func (h *shellHost) open(ctx context.Context, id string, open *agentv1.ShellOpen) {
	h.mu.Lock()
	_, dup := h.shells[id]
	h.mu.Unlock()
	if dup {
		h.log.WarnContext(ctx, "shell request for a session already open", "id", id)
		return
	}
	if err := policy.ShellWithinCeiling(h.ceiling.proto()); err != nil {
		h.log.WarnContext(ctx, "shell request denied: beyond the capability ceiling (start the agent with --allow-shell)", "id", id)
		h.wg.Go(func() { h.exit(id, &agentv1.ShellExited{Denied: true, ExitCode: -1, Error: err.Error()}) })
		return
	}
	sh, err := startShell(open.GetSize(), h.argv)
	if err != nil {
		h.log.WarnContext(ctx, "start shell", "id", id, "err", err)
		h.wg.Go(func() { h.exit(id, &agentv1.ShellExited{ExitCode: -1, Error: err.Error()}) })
		return
	}
	h.mu.Lock()
	h.shells[id] = sh
	h.mu.Unlock()
	// Never log what goes through the terminal: only that a session ran.
	h.log.InfoContext(ctx, "shell started", "id", id, "shell", sh.path, "pid", sh.cmd.Process.Pid)
	h.wg.Go(func() { h.run(ctx, id, sh) })
}

// run serves a started shell until it exits, then reports how it ended.
func (h *shellHost) run(ctx context.Context, id string, sh *shell) {
	started := time.Now()
	h.event(id, &agentv1.ShellEvent{Event: &agentv1.ShellEvent_Started{Started: &agentv1.ShellStarted{Shell: sh.path}}})
	read := make(chan struct{})
	h.wg.Go(func() {
		defer close(read)
		h.pump(id, sh)
	})
	h.wg.Go(sh.write)

	_ = sh.cmd.Wait()
	close(sh.exited)
	sh.mu.Lock()
	if sh.kill != nil {
		sh.kill.Stop()
	}
	killed := sh.killed
	sh.mu.Unlock()
	if killed {
		// The shell is gone; jobs that ignored the hangup are not.
		killSession(sh.cmd.Process.Pid)
	}
	t := time.NewTimer(shellDrain)
	select {
	case <-read:
	case <-t.C:
	}
	t.Stop()
	_ = sh.pty.Close() // ends the reader and the writer
	<-read

	h.mu.Lock()
	delete(h.shells, id)
	h.mu.Unlock()
	ex := &agentv1.ShellExited{ExitCode: int32(sh.cmd.ProcessState.ExitCode())} //nolint:gosec // exit statuses fit in int32
	if killed {
		ex.Error = "session closed"
	}
	h.log.InfoContext(ctx, "shell ended", "id", id, "exit_code", ex.GetExitCode(), "closed", killed,
		"duration", time.Since(started).Round(time.Second))
	h.exit(id, ex)
}

// pump sends what the PTY writes to the hub, within the window.
func (h *shellHost) pump(id string, sh *shell) {
	buf := make([]byte, shellChunk)
	for sh.waitWindow() {
		n, err := sh.pty.Read(buf)
		if n > 0 {
			sh.mu.Lock()
			sh.unacked += n
			sh.mu.Unlock()
			out := append([]byte(nil), buf[:n]...)
			h.event(id, &agentv1.ShellEvent{Event: &agentv1.ShellEvent_Output{Output: out}})
		}
		if err != nil {
			return
		}
	}
}

func (h *shellHost) exit(id string, ex *agentv1.ShellExited) {
	h.event(id, &agentv1.ShellEvent{Event: &agentv1.ShellEvent_Exited{Exited: ex}})
}

func (h *shellHost) event(id string, ev *agentv1.ShellEvent) {
	ev.Id = id
	h.reply(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ShellEvent{ShellEvent: ev}})
}

// closeAll ends every session: the stream they belong to ended.
func (h *shellHost) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sh := range h.shells {
		sh.close()
	}
}

func newShell(path string, cmd *exec.Cmd, pty *os.File) *shell {
	return &shell{
		path: path, cmd: cmd, pty: pty, in: make(chan []byte, shellInputQueue),
		exited: make(chan struct{}), acked: make(chan struct{}, 1),
	}
}

// write copies input to the PTY until the shell exits.
func (sh *shell) write() {
	for {
		select {
		case b := <-sh.in:
			if _, err := sh.pty.Write(b); err != nil {
				return
			}
		case <-sh.exited:
			return
		}
	}
}

// waitWindow waits until fewer than shellWindow output bytes are
// unacknowledged. It returns false once the shell exited with the window
// full: what it still writes is cut.
func (sh *shell) waitWindow() bool {
	for {
		sh.mu.Lock()
		open := sh.unacked < shellWindow
		sh.mu.Unlock()
		if open {
			return true
		}
		select {
		case <-sh.acked:
		case <-sh.exited:
			return false
		}
	}
}

func (sh *shell) ack(n int) {
	sh.mu.Lock()
	sh.unacked = max(sh.unacked-n, 0)
	sh.mu.Unlock()
	select {
	case sh.acked <- struct{}{}:
	default:
	}
}

// close hangs up the shell's process group, and kills it if it is still
// there after shellKillGrace.
func (sh *shell) close() {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.killed {
		return
	}
	select {
	case <-sh.exited:
		return
	default:
	}
	sh.killed = true
	hangupSession(sh.cmd.Process.Pid)
	pid := sh.cmd.Process.Pid
	sh.kill = time.AfterFunc(shellKillGrace, func() {
		select {
		case <-sh.exited: // reaped: the group id may be reused
		default:
			killSession(pid)
		}
	})
}
