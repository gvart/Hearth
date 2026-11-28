// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// How the agent's executable is swapped, per platform (#398). On Linux and
// macOS the running binary is hard-linked to <exe>.prev and the new one
// renamed over it. Windows cannot replace or delete a running .exe, but it
// can rename one: the running binary is renamed to <exe>.prev, then the
// new one into its place. A rollback, which runs in the new binary, moves
// that one aside to <exe>.failed first, and the next start removes it.

// prevSuffix is the previous binary's, failedSuffix a rolled back one's.
const (
	prevSuffix   = ".prev"
	failedSuffix = ".failed"
)

// releaseArchive is the name of the release archive of version for target
// on goos, as .goreleaser.yaml names it: a zip on Windows.
func releaseArchive(goos, version, target string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return "hearth_" + strings.TrimPrefix(version, "v") + "_" + target + ext
}

// releaseBinary is the name of hearth in the release archive for goos.
func releaseBinary(goos string) string {
	if goos == "windows" {
		return "hearth.exe"
	}
	return "hearth"
}

// newBinaryPattern is the os.CreateTemp pattern of the new binary next to
// the executable. Windows runs only a file named .exe.
func newBinaryPattern(goos string) string {
	if goos == "windows" {
		return ".hearth.new-*.exe"
	}
	return ".hearth.new-*"
}

// fileOps are the file system calls of a swap: the os package's, or a
// fake in tests.
type fileOps struct {
	rename func(from, to string) error
	link   func(from, to string) error
	remove func(path string) error
}

// osFileOps are the os package's calls. On Windows a rename is tried a few
// times: an antivirus scanner, or the `version` run that just exited, may
// still hold the new file for a moment.
func osFileOps(goos string) fileOps {
	ops := fileOps{rename: os.Rename, link: os.Link, remove: os.Remove}
	if goos == "windows" {
		ops.rename = func(from, to string) error {
			var err error
			for try := range 5 {
				if err = os.Rename(from, to); err == nil {
					return nil
				}
				time.Sleep(time.Duration(try+1) * 100 * time.Millisecond)
			}
			return err
		}
	}
	return ops
}

// removeIfThere removes path, and is fine if it is not there.
func (o fileOps) removeIfThere(path string) error {
	if err := o.remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// backup readies exe's backup before the swap: it removes an older
// <exe>.prev and, but on Windows, links exe to it. Nothing is in place of
// exe yet: a failure after it leaves exe as it was.
func (o fileOps) backup(goos, exe string) error {
	prev := exe + prevSuffix
	if err := o.removeIfThere(prev); err != nil {
		return fmt.Errorf("remove the old backup %s: %w", prev, err)
	}
	if goos == "windows" {
		return nil // the running exe is renamed to it in replace
	}
	if err := o.link(exe, prev); err != nil {
		return fmt.Errorf("keep the current binary as %s: %w", prev, err)
	}
	return nil
}

// replace puts next in place of exe, after backup. On Windows it renames
// exe to <exe>.prev first, and back if next cannot go in.
func (o fileOps) replace(goos, exe, next string) error {
	if goos == "windows" {
		if err := o.rename(exe, exe+prevSuffix); err != nil {
			return fmt.Errorf("keep the current binary as %s: %w", exe+prevSuffix, err)
		}
		if err := o.rename(next, exe); err != nil {
			if uerr := o.rename(exe+prevSuffix, exe); uerr != nil {
				return fmt.Errorf("put the new binary in place: %w; and put the current one back: %w", err, uerr)
			}
			return fmt.Errorf("put the new binary in place: %w", err)
		}
		return nil
	}
	if err := o.rename(next, exe); err != nil {
		return fmt.Errorf("put the new binary in place: %w", err)
	}
	return nil
}

// restore puts <exe>.prev back in place of exe, the binary running. On
// Windows it moves exe aside to <exe>.failed first, and back if the
// previous one cannot go in.
func (o fileOps) restore(goos, exe string) error {
	prev := exe + prevSuffix
	if goos == "windows" {
		failed := exe + failedSuffix
		if err := o.removeIfThere(failed); err != nil {
			return fmt.Errorf("remove %s: %w", failed, err)
		}
		if err := o.rename(exe, failed); err != nil {
			return fmt.Errorf("move the upgraded binary aside: %w", err)
		}
		if err := o.rename(prev, exe); err != nil {
			if uerr := o.rename(failed, exe); uerr != nil {
				return fmt.Errorf("put the previous binary back: %w; and the upgraded one: %w", err, uerr)
			}
			return fmt.Errorf("put the previous binary back: %w", err)
		}
		return nil
	}
	return o.rename(prev, exe)
}
