// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestReleaseArchiveNames(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		goos, target, archive, binary, pattern string
	}{
		{"linux", "linux_arm64", "hearth_1.2.3_linux_arm64.tar.gz", "hearth", ".hearth.new-*"},
		{"darwin", "darwin_arm64", "hearth_1.2.3_darwin_arm64.tar.gz", "hearth", ".hearth.new-*"},
		{"windows", "windows_amd64", "hearth_1.2.3_windows_amd64.zip", "hearth.exe", ".hearth.new-*.exe"},
	} {
		if got := releaseArchive(tc.goos, "v1.2.3", tc.target); got != tc.archive {
			t.Errorf("releaseArchive(%s) = %s, want %s", tc.goos, got, tc.archive)
		}
		if got := releaseBinary(tc.goos); got != tc.binary {
			t.Errorf("releaseBinary(%s) = %s, want %s", tc.goos, got, tc.binary)
		}
		if got := newBinaryPattern(tc.goos); got != tc.pattern {
			t.Errorf("newBinaryPattern(%s) = %s, want %s", tc.goos, got, tc.pattern)
		}
	}
}

// fakeFiles records the calls of a swap, failing the ones fail names
// ("rename a b", "link a b", "remove a").
type fakeFiles struct {
	calls []string
	fail  map[string]bool
}

func (f *fakeFiles) ops() fileOps {
	do := func(call string) error {
		f.calls = append(f.calls, call)
		if f.fail[call] {
			return errors.New("denied")
		}
		return nil
	}
	return fileOps{
		rename: func(a, b string) error { return do("rename " + a + " " + b) },
		link:   func(a, b string) error { return do("link " + a + " " + b) },
		remove: func(a string) error { return do("remove " + a) },
	}
}

// TestSwapPlans checks the file calls of an upgrade's swap and of its
// rollback, per platform, and that a failed step on Windows undoes the one
// before it.
func TestSwapPlans(t *testing.T) {
	t.Parallel()
	const exe, next = "hearth.exe", ".hearth.new-1.exe"
	for _, tc := range []struct {
		name   string
		goos   string
		run    func(fileOps) error
		fail   []string
		want   []string
		wantOK bool
	}{
		{
			name: "linux upgrade", goos: "linux", wantOK: true,
			run: func(o fileOps) error {
				if err := o.backup("linux", exe); err != nil {
					return err
				}
				return o.replace("linux", exe, next)
			},
			want: []string{"remove hearth.exe.prev", "link hearth.exe hearth.exe.prev", "rename .hearth.new-1.exe hearth.exe"},
		},
		{
			name: "windows upgrade", goos: "windows", wantOK: true,
			run: func(o fileOps) error {
				if err := o.backup("windows", exe); err != nil {
					return err
				}
				return o.replace("windows", exe, next)
			},
			want: []string{"remove hearth.exe.prev", "rename hearth.exe hearth.exe.prev", "rename .hearth.new-1.exe hearth.exe"},
		},
		{
			name: "windows upgrade, new binary refused", goos: "windows",
			run:  func(o fileOps) error { return o.replace("windows", exe, next) },
			fail: []string{"rename .hearth.new-1.exe hearth.exe"},
			want: []string{"rename hearth.exe hearth.exe.prev", "rename .hearth.new-1.exe hearth.exe", "rename hearth.exe.prev hearth.exe"},
		},
		{
			name: "windows upgrade, running binary not renamed", goos: "windows",
			run:  func(o fileOps) error { return o.replace("windows", exe, next) },
			fail: []string{"rename hearth.exe hearth.exe.prev"},
			want: []string{"rename hearth.exe hearth.exe.prev"},
		},
		{
			name: "linux rollback", goos: "linux", wantOK: true,
			run:  func(o fileOps) error { return o.restore("linux", exe) },
			want: []string{"rename hearth.exe.prev hearth.exe"},
		},
		{
			name: "windows rollback", goos: "windows", wantOK: true,
			run:  func(o fileOps) error { return o.restore("windows", exe) },
			want: []string{"remove hearth.exe.failed", "rename hearth.exe hearth.exe.failed", "rename hearth.exe.prev hearth.exe"},
		},
		{
			name: "windows rollback, previous binary refused", goos: "windows",
			run:  func(o fileOps) error { return o.restore("windows", exe) },
			fail: []string{"rename hearth.exe.prev hearth.exe"},
			want: []string{
				"remove hearth.exe.failed", "rename hearth.exe hearth.exe.failed", "rename hearth.exe.prev hearth.exe",
				"rename hearth.exe.failed hearth.exe",
			},
		},
	} {
		f := &fakeFiles{fail: map[string]bool{}}
		for _, c := range tc.fail {
			f.fail[c] = true
		}
		err := tc.run(f.ops())
		if (err == nil) != tc.wantOK {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.wantOK)
		}
		if !slices.Equal(f.calls, tc.want) {
			t.Errorf("%s: calls\n %q\nwant\n %q", tc.name, f.calls, tc.want)
		}
	}
}

// fakeZipRelease is a Windows release zip whose hearth.exe is a script
// printing version (run here, not on Windows), with extra entries.
func fakeZipRelease(t *testing.T, version string, extra ...string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := append([]string{"LICENSE", "README.md"}, extra...)
	files = append(files, "hearth.exe")
	for _, name := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0o755)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		body := "text"
		if name == "hearth.exe" {
			body = "#!/bin/sh\necho 'hearth " + version + "'\n"
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

// windowsUpgrader is testUpgrader for the Windows release and swap, run
// on this platform's files.
func windowsUpgrader(t *testing.T, base string) (*upgrader, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake release's hearth.exe is a shell script")
	}
	exe := filepath.Join(t.TempDir(), "hearth.exe")
	if err := os.WriteFile(exe, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := newUpgrader(exe, t.TempDir(), "v1.0.0", "", false, func(string) string { return "" })
	u.base, u.target, u.goos, u.pubKey = base, "windows_amd64", "windows", testReleasePublicKey()
	return u, exe
}

// TestUpgradeWindowsPlan runs a whole upgrade the Windows way: the zip,
// the renames, then a rollback after maxUpgradeStarts starts without a
// Welcome, and the next start removing the binary moved aside.
func TestUpgradeWindowsPlan(t *testing.T) {
	t.Parallel()
	archive, sum := fakeZipRelease(t, "v1.2.3")
	rel := releaseFor("v1.2.3", "windows_amd64", archive, sum)
	rel.asset = releaseArchive("windows", "v1.2.3", "windows_amd64")
	rel.checksums = sum + "  " + rel.asset + "\n"
	base := releaseServer(t, rel)
	u, exe := windowsUpgrader(t, base)

	res := u.upgrade(t.Context(), &agentv1.UpgradeRequest{Id: "w", Version: "v1.2.3"})
	if !res.GetOk() || res.GetVersion() != "v1.2.3" || !strings.HasSuffix(res.GetUrl(), "/hearth_1.2.3_windows_amd64.zip") {
		t.Fatalf("upgrade = %v, want ok with the windows zip", res)
	}
	if got := readFile(t, exe); !strings.Contains(got, "hearth v1.2.3") {
		t.Errorf("executable = %q, want the new binary", got)
	}
	if got := readFile(t, exe+prevSuffix); got != "old" {
		t.Errorf("backup = %q, want the old binary", got)
	}
	if l := leftovers(t, exe); len(l) != 0 {
		t.Errorf("files left next to the binary: %v", l)
	}

	// The new binary never reaches a hub: rolled back on the fourth start.
	log := slog.New(slog.DiscardHandler)
	next := &upgrader{exe: exe, dataDir: u.dataDir, goos: "windows", current: "v1.2.3"}
	for range maxUpgradeStarts {
		if err := next.started(t.Context(), log); err != nil {
			t.Fatal(err)
		}
	}
	if err := next.started(t.Context(), log); !errors.Is(err, ErrUpgraded) {
		t.Fatalf("start %d = %v, want a rollback", maxUpgradeStarts+1, err)
	}
	if got := readFile(t, exe); got != "old" {
		t.Errorf("executable after the rollback = %q, want the old one", got)
	}
	if got := readFile(t, exe+failedSuffix); !strings.Contains(got, "hearth v1.2.3") {
		t.Errorf("moved aside = %q, want the upgraded binary", got)
	}
	// The previous binary starts and removes what was moved aside.
	prev := &upgrader{exe: exe, dataDir: u.dataDir, goos: "windows", current: "v1.0.0"}
	if err := prev.started(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(exe + failedSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s left after the next start: %v", exe+failedSuffix, err)
	}
	assertRollbackReported(t, prev, "v1.2.3")
}

func TestExtractZipRefuses(t *testing.T) {
	t.Parallel()
	zipFile := func(t *testing.T, b []byte) *os.File {
		t.Helper()
		p := filepath.Join(t.TempDir(), "a.zip")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	good, _ := fakeZipRelease(t, "v1.2.3")
	many := make([]string, maxZipEntries)
	for i := range many {
		many[i] = "f" + strings.Repeat("x", i)
	}
	crowded, _ := fakeZipRelease(t, "v1.2.3", many...)
	var noExe bytes.Buffer
	zw := zip.NewWriter(&noExe)
	if _, err := zw.Create("hearth"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		archive []byte
		u       *upgrader
		wantErr string
	}{
		{"ok", good, &upgrader{maxBinary: maxUpgradeBinary, maxUnpacked: maxUpgradeUnpacked}, ""},
		{"binary over the cap", good, &upgrader{maxBinary: 8, maxUnpacked: maxUpgradeUnpacked}, "larger than"},
		{"unpacked over the cap", good, &upgrader{maxBinary: maxUpgradeBinary, maxUnpacked: 8}, "unpacks to more"},
		{"too many entries", crowded, &upgrader{maxBinary: maxUpgradeBinary, maxUnpacked: maxUpgradeUnpacked}, "files, over"},
		{"no hearth.exe", noExe.Bytes(), &upgrader{maxBinary: maxUpgradeBinary, maxUnpacked: maxUpgradeUnpacked}, "no hearth.exe"},
		{"not a zip", []byte("not a zip at all"), &upgrader{maxBinary: maxUpgradeBinary, maxUnpacked: maxUpgradeUnpacked}, "read the archive"},
	} {
		var out bytes.Buffer
		err := tc.u.extractZip(t.Context(), zipFile(t, tc.archive), &out)
		switch {
		case tc.wantErr == "" && (err != nil || !strings.Contains(out.String(), "hearth v1.2.3")):
			t.Errorf("%s: err %v, out %q", tc.name, err, out.String())
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}
