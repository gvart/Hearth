// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package store

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes an exclusive advisory lock on f without waiting. It reports
// false when another open file holds the lock. Closing f releases it.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}
