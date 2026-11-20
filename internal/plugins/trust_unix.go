// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package plugins

import (
	"fmt"
	"os"
	"syscall"
)

// checkInfo refuses a file or directory not owned by the hub's user or
// root, or writable by group or others, except a root-owned sticky
// directory. The error says how to fix it.
func checkInfo(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", path)
	}
	uid, euid := int(st.Uid), os.Geteuid()
	if uid != euid && uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not the hub's user (uid %d) or root: run chown %d %s",
			path, uid, euid, euid, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		if fi.IsDir() && fi.Mode()&os.ModeSticky != 0 && uid == 0 {
			return nil
		}
		return fmt.Errorf("%s is writable by group or others (mode %v): run chmod go-w %s", path, fi.Mode().Perm(), path)
	}
	return nil
}

// checkPrivate refuses a manifest that holds env, which may be secrets,
// and that group or others can read.
func checkPrivate(path string, fi os.FileInfo) error {
	if fi.Mode().Perm()&0o044 != 0 {
		return fmt.Errorf("%s sets env, which may hold secrets, and is readable by group or others (mode %v): run chmod 600 %s",
			path, fi.Mode().Perm(), path)
	}
	return nil
}
