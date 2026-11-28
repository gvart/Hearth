// SPDX-License-Identifier: AGPL-3.0-only

package agent

import "testing"

func TestEventLevel(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{`time=2026-11-28T10:00:00Z level=INFO msg="connected to hub"`, eventInfo},
		{`time=2026-11-28T10:00:00Z level=DEBUG msg=x`, eventInfo},
		{`time=2026-11-28T10:00:00Z level=WARN msg="hub unreachable"`, eventWarning},
		{`time=2026-11-28T10:00:00Z level=ERROR msg=revoked`, eventError},
		{`time=2026-11-28T10:00:00Z level=INFO msg="a level=ERROR in a message"`, eventInfo},
		{`no level at all`, eventInfo},
		{``, eventInfo},
	}
	for _, tt := range tests {
		if got := eventLevel(tt.line); got != tt.want {
			t.Errorf("eventLevel(%q) = %d, want %d", tt.line, got, tt.want)
		}
	}
}
