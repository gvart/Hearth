// SPDX-License-Identifier: AGPL-3.0-only

package hub

import "testing"

func TestReleaseTargetRE(t *testing.T) {
	t.Parallel()
	for target, want := range map[string]bool{
		"linux_amd64": true, "linux_armv7": true, "darwin_arm64": true, "windows_amd64": true,
		"windows_arm64": false, "windows_armv7": false, "android_arm64": false, "": false, "linux_amd64 ": false,
	} {
		if got := releaseTargetRE.MatchString(target); got != want {
			t.Errorf("releaseTargetRE(%q) = %v, want %v", target, got, want)
		}
	}
}
