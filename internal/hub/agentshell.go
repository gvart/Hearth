// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// minShellMinor is the first agent protocol minor version that answers
// ShellRequest and reports whether its ceiling allows shells.
const minShellMinor = 6

// maxShellBuffer bounds the output a session holds for its reader. An
// agent keeps within a far smaller window (it waits for acknowledgements);
// one that does not has its session ended.
const maxShellBuffer = 4 << 20

// maxDeviceShells is how many terminals may be open on one device at a time.
const maxDeviceShells = 4

// Shell is an open shell session on a device, through its agent. Read
// returns what the shell writes, Write sends it input; Close ends it.
type Shell struct {
	id     string
	device string
	sess   *agentSession
	// opened is closed once the agent answered the open: started or exited.
	opened chan struct{}
	// path is the shell the agent started, set before opened is closed.
	path string

	mu  sync.Mutex
	buf []byte
	// exit is the session's end, once the agent reported it.
	exit *agentv1.ShellExited
	// closing is set once Close asked the agent to end the session.
	closing bool
	// more wakes a Read waiting for output or the end.
	more chan struct{}
}

// Path is the program the agent started, as /bin/bash.
func (sh *Shell) Path() string { return sh.path }

// checkShell refuses a shell unless the agent reported a ceiling that
// allows shells.
func (s *agentSession) checkShell(device string) error {
	if s.minor < minShellMinor {
		return fmt.Errorf("device %s: agent is too old to open a terminal; upgrade it: %w", device, policy.ErrBeyondCeiling)
	}
	s.mu.Lock()
	c := s.ceiling
	s.mu.Unlock()
	if err := policy.ShellWithinCeiling(c); err != nil {
		return fmt.Errorf("device %s: %w (start its agent with --allow-shell)", device, err)
	}
	return nil
}

// deliverShell hands a shell event to its session. It never blocks: the
// stream's receive loop calls it.
func (s *agentSession) deliverShell(ev *agentv1.ShellEvent) {
	s.mu.Lock()
	sh := s.shells[ev.GetId()]
	if _, ok := ev.GetEvent().(*agentv1.ShellEvent_Exited); ok {
		delete(s.shells, ev.GetId())
	}
	s.mu.Unlock()
	if sh == nil {
		return
	}
	switch e := ev.GetEvent().(type) {
	case *agentv1.ShellEvent_Started:
		sh.mu.Lock()
		select {
		case <-sh.opened:
		default:
			sh.path = e.Started.GetShell()
			close(sh.opened)
		}
		sh.mu.Unlock()
	case *agentv1.ShellEvent_Output:
		sh.mu.Lock()
		overflow := len(sh.buf)+len(e.Output) > maxShellBuffer
		if !overflow {
			sh.buf = append(sh.buf, e.Output...)
		}
		sh.mu.Unlock()
		if overflow {
			sh.end(&agentv1.ShellExited{ExitCode: -1, Error: "the agent sent more output than the hub could hold"})
			_ = sh.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Close{Close: &agentv1.ShellClose{}}})
		}
		sh.wake()
	case *agentv1.ShellEvent_Exited:
		sh.end(e.Exited)
	}
}

// endShells ends every session of a stream that ended.
func (s *agentSession) endShells() {
	s.mu.Lock()
	shells := s.shells
	s.shells = map[string]*Shell{}
	s.mu.Unlock()
	for _, sh := range shells {
		sh.end(&agentv1.ShellExited{ExitCode: -1, Error: "agent disconnected"})
	}
}

// end records how the session ended, once.
func (sh *Shell) end(ex *agentv1.ShellExited) {
	sh.mu.Lock()
	if sh.exit == nil {
		sh.exit = ex
	}
	select {
	case <-sh.opened:
	default:
		close(sh.opened)
	}
	sh.mu.Unlock()
	sh.wake()
}

func (sh *Shell) wake() {
	select {
	case sh.more <- struct{}{}:
	default:
	}
}

// CheckShell reports whether a shell would be opened on the agent of device:
// it fails with an error wrapping policy.ErrBeyondCeiling when the agent is
// too old for shells or its reported ceiling does not allow them, and with
// ErrAgentNotConnected when the agent has no open stream to this hub.
func (a *Agents) CheckShell(ctx context.Context, device string) error {
	s, err := a.session(ctx, device)
	if err != nil {
		return err
	}
	return s.checkShell(device)
}

// OpenShell opens a shell of rows x cols on the agent of device and waits
// until it runs. A shell the agent's reported ceiling does not allow is
// never asked for; one the agent refuses itself fails too. Both errors
// wrap policy.ErrBeyondCeiling. ctx must carry policy's grant of
// device.shell. Close the Shell when done.
func (a *Agents) OpenShell(ctx context.Context, device string, rows, cols uint32) (*Shell, error) {
	if !policy.Granted(ctx, policy.DeviceShell) {
		return nil, fmt.Errorf("open shell on device %s: not granted by policy: %w", device, policy.ErrDenied)
	}
	s, err := a.session(ctx, device)
	if err != nil {
		return nil, err
	}
	if err := s.checkShell(device); err != nil {
		return nil, err
	}
	sh := &Shell{
		id: strings.ToLower(rand.Text()), device: device, sess: s,
		opened: make(chan struct{}), more: make(chan struct{}, 1),
	}
	s.mu.Lock()
	if len(s.shells) >= maxDeviceShells {
		s.mu.Unlock()
		return nil, fmt.Errorf("device %s already has %d terminals open", device, maxDeviceShells)
	}
	s.shells[sh.id] = sh
	s.mu.Unlock()
	open := &agentv1.ShellRequest{Op: &agentv1.ShellRequest_Open{Open: &agentv1.ShellOpen{
		Size: &agentv1.TerminalSize{Rows: rows, Cols: cols},
	}}}
	if err := sh.send(open); err != nil {
		sh.forget()
		return nil, fmt.Errorf("open shell on device %s: %w", device, err)
	}
	select {
	case <-sh.opened:
	case <-ctx.Done():
		sh.Close()
		return nil, fmt.Errorf("open shell on device %s: %w", device, context.Cause(ctx))
	}
	sh.mu.Lock()
	ex := sh.exit
	sh.mu.Unlock()
	if ex != nil {
		if ex.GetDenied() {
			return nil, fmt.Errorf("device %s: the agent refused: %s: %w", device, ex.GetError(), policy.ErrBeyondCeiling)
		}
		return nil, fmt.Errorf("open shell on device %s: %s", device, ex.GetError())
	}
	return sh, nil
}

// send sends a request of this session to the agent.
func (sh *Shell) send(req *agentv1.ShellRequest) error {
	req.Id = sh.id
	s := sh.sess
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed {
		return ErrAgentNotConnected
	}
	return s.send(&agentv1.HubMessage{Payload: &agentv1.HubMessage_ShellRequest{ShellRequest: req}})
}

func (sh *Shell) forget() {
	sh.sess.mu.Lock()
	delete(sh.sess.shells, sh.id)
	sh.sess.mu.Unlock()
}

// Read waits for output and returns all there is, acknowledging it to the
// agent, so the shell writes no faster than the caller reads. Once the
// session ended and its output is read, Read returns io.EOF; Exit then says
// how it ended.
func (sh *Shell) Read(ctx context.Context) ([]byte, error) {
	for {
		sh.mu.Lock()
		out, ended := sh.buf, sh.exit != nil
		sh.buf = nil
		sh.mu.Unlock()
		if len(out) > 0 {
			if !ended {
				_ = sh.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Ack{Ack: uint32(len(out))}}) //nolint:gosec // bounded by maxShellBuffer
			}
			return out, nil
		}
		if ended {
			return nil, io.EOF
		}
		select {
		case <-sh.more:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
}

// Write sends input to the shell.
func (sh *Shell) Write(p []byte) error {
	return sh.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Input{Input: append([]byte(nil), p...)}})
}

// Resize sets the shell's terminal size.
func (sh *Shell) Resize(rows, cols uint32) error {
	return sh.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Resize{Resize: &agentv1.TerminalSize{Rows: rows, Cols: cols}}})
}

// Close ends the session: the agent kills the shell's process group. The
// session's end is then reported to Read and Exit; Close does not wait.
func (sh *Shell) Close() {
	sh.mu.Lock()
	skip := sh.exit != nil || sh.closing
	sh.closing = true
	sh.mu.Unlock()
	if skip {
		return
	}
	if err := sh.send(&agentv1.ShellRequest{Op: &agentv1.ShellRequest_Close{Close: &agentv1.ShellClose{}}}); err != nil {
		sh.forget()
		sh.end(&agentv1.ShellExited{ExitCode: -1, Error: "agent disconnected"})
		return
	}
	// An agent that does not report the end in time is not waited for.
	time.AfterFunc(shellCloseWait, func() {
		sh.forget()
		sh.end(&agentv1.ShellExited{ExitCode: -1, Error: "session closed; the agent did not confirm"})
	})
}

// shellCloseWait is how long Close lets the agent report the session's end.
const shellCloseWait = 10 * time.Second

// Exit is how the session ended, or nil while it runs.
func (sh *Shell) Exit() *agentv1.ShellExited {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.exit
}
