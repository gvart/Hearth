// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// serviceStopTimeout bounds how long a stop waits for the agent to wind
// down before the service reports itself stopped anyway.
const serviceStopTimeout = 20 * time.Second

// RunService runs run until ctx is done, logging to logOut. Started by the
// service manager (SCM), it runs run as the agent's service instead: it
// reports the service running, cancels run's context on a stop or a
// shutdown, and logs to the Windows event log (Application, source
// hearth-agent), since a service has no stderr.
func RunService(ctx context.Context, logOut io.Writer, run func(ctx context.Context, logOut io.Writer) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect the Windows service manager: %w", err)
	}
	if !isService {
		return run(ctx, logOut)
	}
	h := &serviceHandler{ctx: ctx, run: run, logOut: io.Discard}
	if el, err := eventlog.Open(ServiceName); err == nil {
		defer func() { _ = el.Close() }()
		h.logOut = eventLogWriter{el}
	}
	if err := svc.Run(ServiceName, h); err != nil {
		return fmt.Errorf("run as the %s service: %w", ServiceName, err)
	}
	return h.err
}

// selfRestartRefusal says why the agent cannot upgrade itself here: only
// the service manager starts the new binary once the agent exits, so an
// agent not running as the service (one started from a shell) does not.
func selfRestartRefusal() string {
	if ok, err := svc.IsWindowsService(); err != nil || !ok {
		return "this agent does not run as the " + ServiceName + " service, so nothing would start the new binary: " +
			"upgrade it on the device with the installer"
	}
	return ""
}

// serviceHandler is the agent as a Windows service.
type serviceHandler struct {
	ctx    context.Context
	run    func(ctx context.Context, logOut io.Writer) error
	logOut io.Writer
	// err is why run returned, if it failed; read after svc.Run returns.
	err error
}

func (h *serviceHandler) Execute(_ []string, reqs <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx, h.logOut) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if errors.Is(err, ErrUpgraded) {
				cancel()
				exitForRestart()
			}
			return h.exit(err)
		case r := <-reqs:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(serviceStopTimeout / time.Millisecond)}
				cancel()
				select {
				case err := <-done:
					return h.exit(err)
				case <-time.After(serviceStopTimeout):
					return false, 0
				}
			default:
			}
		}
	}
}

// exitForRestart ends the process after an upgrade (or a rollback) put
// another binary in place: it exits with ExitUpgraded without reporting
// the service stopped, which the service manager takes for a crash, so its
// recovery actions (`hearth agent service install` sets a restart after
// 5 s) start the binary now in place. It works for a service installed
// before, and leaves every other exit as it was.
func exitForRestart() {
	os.Exit(ExitUpgraded)
}

// exit is the service's exit code for why run returned: none after a stop
// (an upgrade that ends with a stop too: the new binary runs at the next
// start), ExitRevoked for a revoked device, 1 for any other error. The
// service's recovery actions restart it only after a crash, so neither code
// restarts it: as on Linux, a revoked device stays stopped.
func (h *serviceHandler) exit(err error) (bool, uint32) {
	switch {
	case err == nil || errors.Is(err, context.Canceled) || errors.Is(err, ErrUpgraded):
		return false, 0
	case errors.Is(err, ErrRevoked):
		h.err = err
		return true, ExitRevoked
	}
	h.err = err
	return true, 1
}

// eventLogWriter writes each line of the agent's log as an event log entry.
type eventLogWriter struct{ l *eventlog.Log }

func (w eventLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	// A log entry that cannot be written must not stop the agent.
	switch eventLevel(msg) {
	case eventError:
		_ = w.l.Error(1, msg)
	case eventWarning:
		_ = w.l.Warning(1, msg)
	default:
		_ = w.l.Info(1, msg)
	}
	return len(p), nil
}
