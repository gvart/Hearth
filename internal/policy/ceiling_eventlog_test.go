// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestLogsWithinCeilingEventLog(t *testing.T) {
	t.Parallel()
	c := &agentv1.Ceiling{Logs: []string{"eventlog:Application", "eventlog:Microsoft-Windows-*/Operational"}}
	for _, tc := range []struct {
		c       *agentv1.Ceiling
		manager string
		name    string
		ok      bool
	}{
		{c, "eventlog", "Application", true},
		{c, "eventlog", "System", false},
		{c, "eventlog", "Security", false},
		{c, "eventlog", "Microsoft-Windows-Sysmon/Operational", true},
		{c, "eventlog", "Microsoft-Windows-Sysmon/Admin", false},
		{c, "eventlog", "Applic*", false}, // a requested name is never a glob
		{c, "systemd", "Application", false},
		// * does not cross a slash.
		{&agentv1.Ceiling{Logs: []string{"eventlog:*"}}, "eventlog", "Microsoft-Windows-Sysmon/Operational", false},
		{&agentv1.Ceiling{Logs: []string{"systemd:*", "docker:*"}}, "eventlog", "System", false},
		{nil, "eventlog", "System", false},
	} {
		err := LogsWithinCeiling(tc.c, &agentv1.LogSource{Manager: tc.manager, Name: tc.name})
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrBeyondCeiling)) {
			t.Errorf("LogsWithinCeiling(%v, %s:%s) = %v, want ok=%v", tc.c.GetLogs(), tc.manager, tc.name, err, tc.ok)
		}
	}
}

func TestCheckHubCeilingManagers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		c    *agentv1.Ceiling
		ok   bool
	}{
		{"eventlog logs", &agentv1.Ceiling{Logs: []string{"eventlog:System", "eventlog:*"}}, true},
		{"service logs", &agentv1.Ceiling{Logs: []string{"systemd:*", "systemd-user:x", "docker:web"}}, true},
		{"eventlog restart", &agentv1.Ceiling{Restart: []string{"eventlog:System"}}, false},
		{"unknown log manager", &agentv1.Ceiling{Logs: []string{"winlog:System"}}, false},
		{"empty channel", &agentv1.Ceiling{Logs: []string{"eventlog:"}}, false},
		{"bad glob", &agentv1.Ceiling{Logs: []string{"eventlog:[a"}}, false},
	} {
		if err := CheckHubCeiling(tc.c); (err == nil) != tc.ok {
			t.Errorf("%s: CheckHubCeiling = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
