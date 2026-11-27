// SPDX-License-Identifier: AGPL-3.0-only

package release

import "testing"

func TestCompareRelease(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		a, b string
		want int
	}{
		{"v0.0.1", "v0.0.1", 0},
		{"v0.0.1", "v0.0.2", -1},
		{"v0.1.0", "v0.0.9", 1},
		{"v0.10.0", "v0.9.0", 1},
		{"v0.0.1-rc.9", "v0.0.1-rc.10", -1},
		{"v0.0.1-rc.10", "v0.0.1", -1},
		{"v0.0.1", "v0.0.1-rc.10", 1},
		{"v0.0.1-rc.1", "v0.0.1-rc.1.1", -1},
		{"v0.0.1-alpha", "v0.0.1-beta", -1},
		{"v0.0.1-1", "v0.0.1-alpha", -1},
	} {
		if got := Compare(tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
