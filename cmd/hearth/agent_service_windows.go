// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/gvart/hearth/internal/agent"
)

// serviceRestartDelays are the service's recovery actions after a crash:
// restart in 5 s, again in 5 s, then every minute, counted afresh after
// serviceResetPeriod without a crash. A run that stops with an error
// (a revoked device) is no crash, so it is not restarted.
var serviceRestartDelays = []time.Duration{5 * time.Second, 5 * time.Second, time.Minute}

// serviceResetPeriod is a day, in seconds, as the service manager takes it.
const serviceResetPeriod = 24 * 60 * 60

// dataDirSDDL owns the data dir by Administrators and lets only SYSTEM and
// Administrators in (protected: nothing inherited from %ProgramData%,
// which any user may read), the files inside it too.
const dataDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func installAgentService(out io.Writer, dataDir string, localCeiling bool) error {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.Abs(exe)
	}
	if err != nil {
		return fmt.Errorf("find this executable: %w", err)
	}
	if err := secureDataDir(dataDir); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager (run this as Administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(agent.ServiceName)
	switch {
	case err == nil:
		cfg, err := s.Config()
		if err != nil {
			_ = s.Close()
			return fmt.Errorf("read the %s service: %w", agent.ServiceName, err)
		}
		if _, err := fmt.Fprintf(out, "Service %s is already installed; keeping its command line: %s\n",
			agent.ServiceName, cfg.BinaryPathName); err != nil {
			_ = s.Close()
			return fmt.Errorf("write result: %w", err)
		}
		if localCeiling && !hasLocalCeiling(cfg.BinaryPathName) {
			_, _ = fmt.Fprintf(out, "It runs without --local-ceiling: uninstall the service and install it again to add it.\n")
		}
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		s, err = m.CreateService(agent.ServiceName, exe, mgr.Config{
			DisplayName:  "Hearth agent",
			Description:  "Reports this device to its Hearth hub and runs what the hub may do here.",
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, serviceRunArgs(dataDir, localCeiling)...)
		if err != nil {
			return fmt.Errorf("create the %s service: %w", agent.ServiceName, err)
		}
		if _, err := fmt.Fprintf(out, "Installed service %s (data dir %s).\n", agent.ServiceName, dataDir); err != nil {
			_ = s.Close()
			return fmt.Errorf("write result: %w", err)
		}
	default:
		return fmt.Errorf("open the %s service: %w", agent.ServiceName, err)
	}
	defer func() { _ = s.Close() }()

	actions := make([]mgr.RecoveryAction, 0, len(serviceRestartDelays))
	for _, d := range serviceRestartDelays {
		actions = append(actions, mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: d})
	}
	if err := s.SetRecoveryActions(actions, serviceResetPeriod); err != nil {
		return fmt.Errorf("set the %s service's recovery actions: %w", agent.ServiceName, err)
	}
	// The agent logs to the event log as this source; without it, entries
	// still come but read badly in Event Viewer.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, eventSourceKey, registry.QUERY_VALUE)
	if err == nil {
		_ = k.Close()
		return nil
	}
	if err := eventlog.InstallAsEventCreate(agent.ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		_, _ = fmt.Fprintf(out, "warning: could not register the event log source %s: %v\n", agent.ServiceName, err)
	}
	return nil
}

// eventSourceKey is the registry key of the agent's event log source.
const eventSourceKey = `SYSTEM\CurrentControlSet\Services\EventLog\Application\` + agent.ServiceName

// secureDataDir creates dir and gives it dataDirSDDL, before an
// enrollment writes the device's private key there.
func secureDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return fmt.Errorf("data dir security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("data dir owner: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("data dir ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict data dir %s to SYSTEM and Administrators: %w", dir, err)
	}
	return nil
}

// serviceStopWait bounds how long uninstall waits for the service to stop.
const serviceStopWait = 30 * time.Second

func uninstallAgentService(ctx context.Context, out io.Writer) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager (run this as Administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(agent.ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		_, err := fmt.Fprintf(out, "Service %s is not installed.\n", agent.ServiceName)
		return err
	}
	if err != nil {
		return fmt.Errorf("open the %s service: %w", agent.ServiceName, err)
	}
	defer func() { _ = s.Close() }()
	if err := stopService(ctx, s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete the %s service: %w", agent.ServiceName, err)
	}
	// Best effort: a source left behind only names a log nobody writes.
	_ = eventlog.Remove(agent.ServiceName)
	_, err = fmt.Fprintf(out, "Removed service %s; the data dir is kept.\n", agent.ServiceName)
	return err
}

// stopService stops s and waits, up to serviceStopWait, until it has.
func stopService(ctx context.Context, s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query the %s service: %w", agent.ServiceName, err)
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop the %s service: %w", agent.ServiceName, err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, serviceStopWait)
	defer cancel()
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("the %s service did not stop: %w", agent.ServiceName, ctx.Err())
		case <-tick.C:
		}
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query the %s service: %w", agent.ServiceName, err)
		}
		if st.State == svc.Stopped {
			return nil
		}
	}
}
