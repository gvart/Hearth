// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errorLockViolation      = syscall.Errno(33)
)

var procLockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

// tryLock takes an exclusive lock on f without waiting. It reports false when
// another open file holds the lock. Closing f releases it.
func tryLock(f *os.File) (bool, error) {
	var overlapped syscall.Overlapped
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped))) //nolint:gosec // the call's documented form
	if r != 0 {
		return true, nil
	}
	if errors.Is(err, errorLockViolation) || errors.Is(err, syscall.ERROR_IO_PENDING) {
		return false, nil
	}
	return false, err
}
