// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestLogsWithinCeiling(t *testing.T) {
	t.Parallel()
	c := &agentv1.Ceiling{Logs: []string{"systemd:nginx.service", "systemd-user:hearth-*", "docker:*", "bad"}}
	for _, tc := range []struct {
		c       *agentv1.Ceiling
		manager string
		name    string
		ok      bool
	}{
		{c, "systemd", "nginx.service", true},
		{c, "systemd", "sshd.service", false},
		{c, "systemd-user", "hearth-i33.service", true},
		{c, "systemd-user", "nginx.service", false},
		// systemd:* would not cover a user's units, nor the reverse.
		{c, "systemd", "hearth-i33.service", false},
		{c, "docker", "anything", true},
		{c, "docker", "a/b", false}, // * does not cross a slash
		{c, "bad", "x", false},
		{nil, "docker", "web", false},
		{&agentv1.Ceiling{}, "docker", "web", false},
	} {
		err := LogsWithinCeiling(tc.c, &agentv1.LogSource{Manager: tc.manager, Name: tc.name})
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrBeyondCeiling)) {
			t.Errorf("LogsWithinCeiling(%v, %s:%s) = %v, want ok=%v", tc.c.GetLogs(), tc.manager, tc.name, err, tc.ok)
		}
	}
	if err := LogsWithinCeiling(c, &agentv1.LogSource{Manager: "docker"}); err == nil || errors.Is(err, ErrBeyondCeiling) {
		t.Errorf("empty name = %v, want a plain error", err)
	}
	if class, ok := ClassOf(DeviceLogs); !ok || class != Read {
		t.Errorf("class of %s = %s, want read", DeviceLogs, class)
	}
}
