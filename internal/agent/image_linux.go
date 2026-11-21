// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// releaseImagePages unmaps the pages of the hearth binary that are mapped
// read-only and unmodified: code and read-only data. The binary holds the hub
// too, and running every package's init faults in much of it, the more so on
// kernels that map whole large folios at a time, so right after start most of
// the agent's RSS is pages it will not touch again. The pages stay in the page
// cache; the few the agent still runs fault back in on use. Mappings with
// anonymous (copied on write) pages, such as a relocated RELRO region in a PIE
// build, are left alone, as dropping them would discard their contents.
func releaseImagePages() {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return
	}
	smaps, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		return
	}
	for _, s := range imageSpans(smaps, exe) {
		_, _, _ = unix.Syscall(unix.SYS_MADVISE, s.start, s.end-s.start, unix.MADV_DONTNEED)
	}
}

type span struct{ start, end uintptr }

// imageSpans returns the address ranges of the mappings in smaps that map exe
// without write permission and hold no anonymous pages. Private_Dirty is no
// guide: it counts page cache pages not yet written back, as for a binary
// just built.
func imageSpans(smaps []byte, exe string) []span {
	var (
		spans []span
		cur   span
		ok    bool // cur is a candidate
	)
	flush := func() {
		if ok {
			spans = append(spans, cur)
		}
		ok = false
	}
	for line := range bytes.Lines(smaps) {
		f := bytes.Fields(line)
		if len(f) == 0 {
			continue
		}
		if key, isField := bytes.CutSuffix(f[0], []byte(":")); isField {
			if ok && string(key) == "Anonymous" && (len(f) < 2 || string(f[1]) != "0") {
				ok = false
			}
			continue
		}
		flush()
		if len(f) < 6 || len(f[1]) < 2 || f[1][1] != '-' || string(bytes.Join(f[5:], []byte(" "))) != exe {
			continue
		}
		lo, hi, found := bytes.Cut(f[0], []byte("-"))
		start, err1 := strconv.ParseUint(string(lo), 16, 64)
		end, err2 := strconv.ParseUint(string(hi), 16, 64)
		if !found || err1 != nil || err2 != nil || end <= start {
			continue
		}
		cur, ok = span{uintptr(start), uintptr(end)}, true
	}
	flush()
	return spans
}
