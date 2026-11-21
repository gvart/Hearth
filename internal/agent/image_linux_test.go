// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"
	"reflect"
	"testing"
)

func TestImageSpans(t *testing.T) {
	const exe = "/usr/local/bin/hearth"
	mapping := func(header, anon, dirty string) string {
		return header + "\nSize:               8 kB\nPrivate_Clean:      8 kB\nPrivate_Dirty:      " + dirty +
			" kB\nAnonymous:          " + anon + " kB\nVmFlags: rd ex mr mw me\n"
	}
	tests := []struct {
		name  string
		smaps string
		want  []span
	}{
		{
			name:  "code and read-only data",
			smaps: mapping("00400000-00402000 r-xp 00000000 08:01 42 "+exe, "0", "0") + mapping("00402000-00404000 r--p 00002000 08:01 42 "+exe, "0", "0"),
			want:  []span{{0x400000, 0x402000}, {0x402000, 0x404000}},
		},
		{
			name:  "writable data is kept",
			smaps: mapping("00404000-00406000 rw-p 00004000 08:01 42 "+exe, "0", "0"),
		},
		{
			name:  "relocated read-only data is kept",
			smaps: mapping("00402000-00404000 r--p 00002000 08:01 42 "+exe, "8", "8"),
		},
		{
			name:  "a binary not yet written back is released",
			smaps: mapping("00400000-00402000 r-xp 00000000 08:01 42 "+exe, "0", "8"),
			want:  []span{{0x400000, 0x402000}},
		},
		{
			name:  "other files and anonymous memory are kept",
			smaps: mapping("7f000000-7f002000 r-xp 00000000 08:01 7 /usr/lib/libc.so.6", "0", "0") + mapping("7f100000-7f102000 r--p 00000000 00:00 0", "0", "0"),
		},
		{
			name:  "the path must match exactly",
			smaps: mapping("00400000-00402000 r-xp 00000000 08:01 42 "+exe+" (deleted)", "0", "0"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := imageSpans([]byte(tt.smaps), exe); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("imageSpans = %v, want %v", got, tt.want)
			}
		})
	}
	if got := imageSpans([]byte(mapping("00400000-00402000 r-xp 00000000 08:01 42 "+exe+" (deleted)", "0", "0")), exe+" (deleted)"); len(got) != 1 {
		t.Errorf("deleted binary: imageSpans = %v, want one span", got)
	}
}

// TestReleaseImagePages releases the test binary's own code pages: the
// process keeps running, as it faults them back in.
func TestReleaseImagePages(t *testing.T) {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	smaps, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		t.Fatal(err)
	}
	if len(imageSpans(smaps, exe)) == 0 {
		t.Fatalf("no read-only mappings of %s in /proc/self/smaps", exe)
	}
	releaseImagePages()
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		t.Fatal(err)
	}
}
