// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package plugins

import (
	"fmt"
	"os"
	"syscall"
)

// CheckInstaller checks that this process may install plugins in dataDir:
// that it runs as the user who owns it, the hub's. Files another user (root,
// say) wrote there would be the hub's to run but not to read.
func CheckInstaller(dataDir string) error {
	fi, err := os.Stat(dataDir)
	if err != nil {
		return fmt.Errorf("hub data dir: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("run this as the hub's user, who owns %s (uid %d), such as with sudo -u hearth", dataDir, st.Uid)
	}
	return nil
}
