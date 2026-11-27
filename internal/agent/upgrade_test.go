// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/release"
)

// testReleaseKey signs the fake releases' checksums.txt, and the test
// upgraders trust its public half; otherReleaseKey is a key they do not
// trust. Both are made for this test run.
var testReleaseKey, otherReleaseKey = newTestKey(), newTestKey()

func newTestKey() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// testReleasePublicKey is the public half of testReleaseKey.
func testReleasePublicKey() ed25519.PublicKey {
	pub, _ := testReleaseKey.Public().(ed25519.PublicKey)
	return pub
}

// fakeRelease is a release archive whose hearth is a script printing
// version, and its SHA-256.
func fakeRelease(t *testing.T, name, version string) ([]byte, string) {
	t.Helper()
	script := []byte("#!/bin/sh\necho 'hearth " + version + "'\necho '  commit:   test'\n")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{{"LICENSE", []byte("AGPL")}, {name, script}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

// testTarget is the platform of the test upgraders' releases: the fake
// hearth is a shell script, whatever the archive's name says.
const testTarget = "linux_amd64"

// assetName is the release archive of version for target.
func assetName(version, target string) string {
	return "hearth_" + strings.TrimPrefix(version, "v") + "_" + target + ".tar.gz"
}

// fakeReleaseFiles is what a fake release server serves under /<version>/.
type fakeReleaseFiles struct {
	version, target string
	archive         []byte
	checksums       string // checksums.txt; "" for a 404
	// sig is checksums.txt.sig; "" for testReleaseKey's signature of
	// checksums, and noSig for a 404.
	sig       string
	noSig     bool
	chunked   bool // no Content-Length on the archive
	noArchive bool // a 404 for the archive
}

// releaseFor is the release of version for target holding archive, its
// checksums.txt listing sum for it.
func releaseFor(version, target string, archive []byte, sum string) fakeReleaseFiles {
	return fakeReleaseFiles{
		version: version, target: target, archive: archive,
		checksums: strings.Repeat("a", 64) + "  hearth_" + strings.TrimPrefix(version, "v") + "_windows_amd64.zip\n" +
			sum + "  " + assetName(version, target) + "\n",
	}
}

// releaseServer serves rel as the project's releases do, and returns its
// base URL.
func releaseServer(t *testing.T, rel fakeReleaseFiles) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/"+rel.version+"/checksums.txt" && rel.checksums != "":
			_, _ = w.Write([]byte(rel.checksums))
		case r.URL.Path == "/"+rel.version+"/checksums.txt.sig" && !rel.noSig:
			sig := []byte(rel.sig)
			if rel.sig == "" {
				sig = release.Sign(testReleaseKey, []byte(rel.checksums))
			}
			_, _ = w.Write(sig)
		case r.URL.Path == "/"+rel.version+"/"+assetName(rel.version, rel.target) && !rel.noArchive:
			if rel.chunked {
				// No Content-Length: the cap must hold while reading.
				w.(http.Flusher).Flush()
			}
			_, _ = w.Write(rel.archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// testUpgrader is an upgrader of a fake executable in a temporary
// directory, holding "old", of an agent running v1.0.0, downloading from
// base.
func testUpgrader(t *testing.T, base string) (*upgrader, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake release's hearth is a shell script")
	}
	exe := filepath.Join(t.TempDir(), "hearth")
	if err := os.WriteFile(exe, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := newUpgrader(exe, t.TempDir(), "v1.0.0", false, func(string) string { return "" })
	u.base, u.target, u.pubKey = base, testTarget, testReleasePublicKey()
	return u, exe
}

// leftovers are the files next to exe other than it and its backup.
func leftovers(t *testing.T, exe string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(exe))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if n := e.Name(); n != filepath.Base(exe) && n != filepath.Base(exe)+".prev" {
			out = append(out, n)
		}
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readPending(t *testing.T, dataDir string) (pendingUpgrade, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dataDir, upgradePendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return pendingUpgrade{}, false
	}
	var p pendingUpgrade
	if err == nil {
		err = json.Unmarshal(b, &p)
	}
	if err != nil {
		t.Fatal(err)
	}
	return p, true
}

func TestUpgradeReplacesTheBinary(t *testing.T) {
	t.Parallel()
	archive, sum := fakeRelease(t, "hearth", "v1.2.3")
	base := releaseServer(t, releaseFor("v1.2.3", testTarget, archive, sum))
	u, exe := testUpgrader(t, base)
	res := u.upgrade(t.Context(), &agentv1.UpgradeRequest{Id: "u1", Version: "v1.2.3"})
	if !res.GetOk() || res.GetVersion() != "v1.2.3" || res.GetId() != "u1" {
		t.Fatalf("upgrade = %v, want ok with v1.2.3", res)
	}
	if want := base + "/v1.2.3/" + assetName("v1.2.3", testTarget); res.GetUrl() != want || res.GetSha256() != sum {
		t.Errorf("upgrade reports %s %s, want %s %s", res.GetUrl(), res.GetSha256(), want, sum)
	}
	if got := readFile(t, exe); !strings.Contains(got, "hearth v1.2.3") {
		t.Errorf("executable after the upgrade = %q, want the new binary", got)
	}
	if got := readFile(t, exe+".prev"); got != "old" {
		t.Errorf("backup = %q, want the old binary", got)
	}
	if l := leftovers(t, exe); len(l) != 0 {
		t.Errorf("files left next to the binary: %v", l)
	}
	if p, ok := readPending(t, u.dataDir); !ok || p != (pendingUpgrade{From: "v1.0.0", To: "v1.2.3"}) {
		t.Errorf("upgrade marker = %+v (%v), want from v1.0.0 to v1.2.3", p, ok)
	}
	// A second upgrade, of the same release again, replaces the backup.
	u.current = "v1.2.3"
	if res := u.upgrade(t.Context(), &agentv1.UpgradeRequest{Version: "v1.2.3"}); !res.GetOk() {
		t.Fatalf("second upgrade = %v", res)
	}
	if got := readFile(t, exe+".prev"); !strings.Contains(got, "hearth v1.2.3") {
		t.Errorf("backup after the second upgrade = %q, want v1.2.3", got)
	}
}

// TestUpgradeRefused checks that every failed check leaves the old binary
// as it was, nothing next to it and no upgrade marker.
func TestUpgradeRefused(t *testing.T) {
	t.Parallel()
	archive, sum := fakeRelease(t, "hearth", "v1.2.3")
	noBinary, noBinarySum := fakeRelease(t, "hearth-other", "v1.2.3")
	ok := releaseFor("v1.2.3", testTarget, archive, sum)
	with := func(f func(r *fakeReleaseFiles)) *fakeReleaseFiles { r := ok; f(&r); return &r }
	// A release server that sends everything on to plain http.
	plain := releaseServer(t, ok)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain+r.URL.Path, http.StatusFound) //nolint:gosec // a test server redirecting to plain http on purpose
	}))
	t.Cleanup(redirect.Close)
	tests := []struct {
		name    string
		version string
		rel     *fakeReleaseFiles // nil: the redirecting server
		setup   func(u *upgrader)
		denied  bool
		wantErr string
	}{
		{name: "sha256 mismatch", rel: with(func(r *fakeReleaseFiles) {
			*r = releaseFor("v1.2.3", testTarget, archive, strings.Repeat("0", 64))
		}), wantErr: "checksum mismatch"},
		{name: "checksums list no archive", rel: with(func(r *fakeReleaseFiles) { r.checksums = sum + "  other.tar.gz\n" }), wantErr: "lists no"},
		{name: "checksums with a bad hash", rel: with(func(r *fakeReleaseFiles) {
			r.checksums = "xyz  " + assetName("v1.2.3", testTarget) + "\n"
		}), wantErr: "no valid SHA-256"},
		{name: "no checksums", rel: with(func(r *fakeReleaseFiles) { r.checksums = "" }), wantErr: "404"},
		{name: "no signature", rel: with(func(r *fakeReleaseFiles) { r.noSig = true }), wantErr: "is not signed"},
		{name: "signed with another key", rel: with(func(r *fakeReleaseFiles) {
			r.sig = string(release.Sign(otherReleaseKey, []byte(r.checksums)))
		}), wantErr: "does not verify"},
		{name: "checksums changed after signing", rel: with(func(r *fakeReleaseFiles) {
			r.sig = string(release.Sign(testReleaseKey, []byte(r.checksums)))
			r.checksums = strings.Replace(r.checksums, sum, strings.Repeat("1", 64), 1)
		}), wantErr: "does not verify"},
		{name: "malformed signature", rel: with(func(r *fakeReleaseFiles) { r.sig = "not a signature" }), wantErr: "malformed"},
		{name: "signature too large", rel: with(func(r *fakeReleaseFiles) { r.sig = strings.Repeat("A", maxSignature+1) }), wantErr: "larger than"},
		{name: "no archive", rel: with(func(r *fakeReleaseFiles) { r.noArchive = true }), wantErr: "404"},
		{name: "another platform's archive", rel: with(func(r *fakeReleaseFiles) {
			*r = releaseFor("v1.2.3", "linux_arm64", archive, sum)
		}), wantErr: "lists no"},
		{name: "redirect to http", wantErr: "only https"},
		{name: "too large, by Content-Length", rel: &ok, setup: func(u *upgrader) { u.maxArchive = 100 }, wantErr: "larger than"},
		{
			name: "too large, while reading", rel: with(func(r *fakeReleaseFiles) { r.chunked = true }),
			setup: func(u *upgrader) { u.maxArchive = 100 }, wantErr: "larger than",
		},
		{name: "binary too large", rel: &ok, setup: func(u *upgrader) { u.maxBinary = 10 }, wantErr: "larger than"},
		{name: "unpacks too large", rel: &ok, setup: func(u *upgrader) { u.maxUnpacked = 100 }, wantErr: "unpacks to more than"},
		{name: "no hearth in the archive", rel: with(func(r *fakeReleaseFiles) {
			*r = releaseFor("v1.2.3", testTarget, noBinary, noBinarySum)
		}), wantErr: "no hearth binary"},
		{name: "another version inside", version: "v1.2.4", rel: with(func(r *fakeReleaseFiles) {
			*r = releaseFor("v1.2.4", testTarget, archive, sum)
		}), wantErr: "reports version"},
		{name: "no version", version: "latest", rel: &ok, denied: true, wantErr: "version"},
		{name: "a path for a version", version: "v1.2.3/../../x", rel: &ok, denied: true, wantErr: "version"},
		{name: "downgrade", version: "v0.9.0", rel: with(func(r *fakeReleaseFiles) {
			*r = releaseFor("v0.9.0", testTarget, archive, sum)
		}), denied: true, wantErr: "downgrades are refused"},
		{name: "a release that cannot upgrade itself, from a dev build", version: "v0.0.1-rc.10", rel: with(func(r *fakeReleaseFiles) {
			*r = releaseFor("v0.0.1-rc.10", testTarget, archive, sum)
		}), setup: func(u *upgrader) { u.current = "dev" }, denied: true, wantErr: "cannot upgrade itself"},
		{
			name: "local ceiling", rel: &ok, denied: true, wantErr: "--local-ceiling",
			setup: func(u *upgrader) { u.refusal = selfUpgradeRefusal("linux", true, func(string) string { return "" }) },
		},
		{
			name: "kubernetes", rel: &ok, denied: true, wantErr: "upgrade its image",
			setup: func(u *upgrader) {
				u.refusal = selfUpgradeRefusal("linux", false, func(k string) string {
					if k == "KUBERNETES_SERVICE_HOST" {
						return "10.0.0.1"
					}
					return ""
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := redirect.URL
			if tt.rel != nil {
				base = releaseServer(t, *tt.rel)
			}
			u, exe := testUpgrader(t, base)
			if tt.setup != nil {
				tt.setup(u)
			}
			res := u.upgrade(t.Context(), &agentv1.UpgradeRequest{Version: cmp.Or(tt.version, "v1.2.3")})
			if res.GetOk() || res.GetDenied() != tt.denied || !strings.Contains(res.GetError(), tt.wantErr) {
				t.Fatalf("upgrade = %v, want denied=%v and an error with %q", res, tt.denied, tt.wantErr)
			}
			if got := readFile(t, exe); got != "old" {
				t.Errorf("executable = %q, want the old binary intact", got)
			}
			if l := leftovers(t, exe); len(l) != 0 {
				t.Errorf("files left next to the binary: %v", l)
			}
			if p, ok := readPending(t, u.dataDir); ok {
				t.Errorf("upgrade marker %+v left by a failed upgrade", p)
			}
		})
	}
}

func TestHTTPSRedirects(t *testing.T) {
	t.Parallel()
	to := func(u string) *http.Request {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if err := httpsRedirects(to("https://objects.example.com/x"), make([]*http.Request, 1)); err != nil {
		t.Errorf("https redirect refused: %v", err)
	}
	if err := httpsRedirects(to("http://objects.example.com/x"), make([]*http.Request, 1)); err == nil {
		t.Error("http redirect followed")
	}
	if err := httpsRedirects(to("https://x/y"), make([]*http.Request, maxRedirects)); err == nil {
		t.Error("endless redirects followed")
	}
}

func TestNewUpgraderBase(t *testing.T) {
	t.Parallel()
	u := newUpgrader("/x/hearth", t.TempDir(), "v1.0.0", false, func(string) string { return "" })
	if u.base != ReleaseBaseURL || !strings.HasPrefix(u.base, "https://") {
		t.Errorf("base = %s, want the project's https releases", u.base)
	}
	u = newUpgrader("/x/hearth", t.TempDir(), "v1.0.0", false, func(k string) string {
		if k == releaseBaseEnv {
			return "http://releases:8000/r/"
		}
		return ""
	})
	if u.base != "http://releases:8000/r" {
		t.Errorf("base with %s = %s", releaseBaseEnv, u.base)
	}
	// An agent started with --local-ceiling refuses, as Run builds it.
	if u := newUpgrader("/x/hearth", t.TempDir(), "v1.0.0", true, func(string) string { return "" }); !strings.Contains(u.refusal, "--local-ceiling") {
		t.Errorf("refusal with --local-ceiling = %q", u.refusal)
	}
}

// TestExtractStops checks that extract gives up once its context is done.
func TestExtractStops(t *testing.T) {
	t.Parallel()
	archive, _ := fakeRelease(t, "hearth", "v1.2.3")
	u := &upgrader{maxBinary: maxUpgradeBinary, maxUnpacked: maxUpgradeUnpacked}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out bytes.Buffer
	if err := u.extract(ctx, bytes.NewReader(archive), &out); !errors.Is(err, context.Canceled) {
		t.Errorf("extract with a cancelled context = %v, want context.Canceled", err)
	}
	if out.Len() != 0 {
		t.Errorf("extract wrote %d bytes after its context was done", out.Len())
	}
}

// TestUpgradeRollback checks that an upgraded agent that starts more than
// maxUpgradeStarts times without a hub welcoming it puts the previous
// binary back and exits for it to start, and that a Welcome confirms it.
func TestUpgradeRollback(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	setup := func(t *testing.T) (*upgrader, string) {
		t.Helper()
		exe := filepath.Join(t.TempDir(), "hearth")
		for path, body := range map[string]string{exe: "new", exe + ".prev": "old"} {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		u := &upgrader{exe: exe, dataDir: t.TempDir()}
		if err := writePending(u.dataDir, pendingUpgrade{From: "v1.0.0", To: "v1.2.3"}); err != nil {
			t.Fatal(err)
		}
		return u, exe
	}

	t.Run("never welcomed", func(t *testing.T) {
		t.Parallel()
		u, exe := setup(t)
		for i := 1; i <= maxUpgradeStarts; i++ {
			if err := u.started(t.Context(), log); err != nil {
				t.Fatalf("start %d = %v, want nil", i, err)
			}
			if p, _ := readPending(t, u.dataDir); p.Starts != i {
				t.Fatalf("after start %d the marker counts %d", i, p.Starts)
			}
		}
		err := u.started(t.Context(), log)
		if !errors.Is(err, ErrUpgraded) || !strings.Contains(err.Error(), "v1.0.0") {
			t.Fatalf("start %d = %v, want a rollback to v1.0.0 that is ErrUpgraded", maxUpgradeStarts+1, err)
		}
		if got := readFile(t, exe); got != "old" {
			t.Errorf("executable after the rollback = %q, want the previous one", got)
		}
		if _, ok := readPending(t, u.dataDir); ok {
			t.Error("marker left after the rollback")
		}
		// The previous binary starts with no marker: nothing more happens,
		// but it tells the hub what it was rolled back from.
		prev := &upgrader{exe: exe, dataDir: u.dataDir}
		if err := prev.started(t.Context(), log); err != nil {
			t.Errorf("start after the rollback = %v", err)
		}
		assertRollbackReported(t, prev, "v1.2.3")
	})

	t.Run("welcomed", func(t *testing.T) {
		t.Parallel()
		u, exe := setup(t)
		if err := u.started(t.Context(), log); err != nil {
			t.Fatal(err)
		}
		u.welcomed(t.Context(), log)
		if _, ok := readPending(t, u.dataDir); ok {
			t.Error("marker left after a Welcome")
		}
		for range maxUpgradeStarts + 1 {
			if err := u.started(t.Context(), log); err != nil {
				t.Fatalf("start after a Welcome = %v", err)
			}
		}
		if got := readFile(t, exe); got != "new" {
			t.Errorf("executable = %q, want the upgraded one kept", got)
		}
	})

	t.Run("no hub within the timeout", func(t *testing.T) {
		t.Parallel()
		u, exe := setup(t)
		u.noHub = 10 * time.Millisecond
		if err := u.started(t.Context(), log); err != nil {
			t.Fatal(err)
		}
		stopped := make(chan error, 1)
		end := u.watchWelcome(t.Context(), log, func(err error) { stopped <- err })
		var err error
		select {
		case err = <-stopped:
		case <-time.After(10 * time.Second):
			t.Fatal("no rollback after the timeout")
		}
		end()
		if !errors.Is(err, ErrUpgraded) || !strings.Contains(err.Error(), "v1.2.3") {
			t.Fatalf("stop(%v), want a rollback from v1.2.3 that is ErrUpgraded", err)
		}
		if got := readFile(t, exe); got != "old" {
			t.Errorf("executable after the rollback = %q, want the previous one", got)
		}
		if _, ok := readPending(t, u.dataDir); ok {
			t.Error("marker left after the rollback")
		}
		// A Welcome arriving after the rollback changes nothing.
		u.welcomed(t.Context(), log)
		if got := readFile(t, exe); got != "old" {
			t.Errorf("executable after a late Welcome = %q, want the previous one", got)
		}
		prev := &upgrader{exe: exe, dataDir: u.dataDir}
		if err := prev.started(t.Context(), log); err != nil {
			t.Fatal(err)
		}
		assertRollbackReported(t, prev, "v1.2.3")
	})

	t.Run("welcomed before the timeout", func(t *testing.T) {
		t.Parallel()
		u, exe := setup(t)
		u.noHub = time.Second
		if err := u.started(t.Context(), log); err != nil {
			t.Fatal(err)
		}
		stopped := make(chan error, 1)
		end := u.watchWelcome(t.Context(), log, func(err error) { stopped <- err })
		u.welcomed(t.Context(), log)
		time.Sleep(1500 * time.Millisecond)
		end()
		select {
		case err := <-stopped:
			t.Fatalf("stop(%v) after a Welcome", err)
		default:
		}
		if got := readFile(t, exe); got != "new" {
			t.Errorf("executable = %q, want the upgraded one kept", got)
		}
	})

	t.Run("welcomed but the marker cannot be removed", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() == 0 {
			t.Skip("root removes files from a read-only directory")
		}
		u, exe := setup(t)
		u.noHub = 50 * time.Millisecond
		if err := u.started(t.Context(), log); err != nil {
			t.Fatal(err)
		}
		stopped := make(chan error, 1)
		end := u.watchWelcome(t.Context(), log, func(err error) { stopped <- err })
		if err := os.Chmod(u.dataDir, 0o500); err != nil { //nolint:gosec // a directory the agent cannot write
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(u.dataDir, 0o700) }) //nolint:gosec // a directory, writable again
		u.welcomed(t.Context(), log)
		time.Sleep(300 * time.Millisecond)
		end()
		select {
		case err := <-stopped:
			t.Fatalf("stop(%v) after a Welcome", err)
		default:
		}
		if got := readFile(t, exe); got != "new" {
			t.Errorf("executable = %q, want the upgraded one kept", got)
		}
		// The next Welcome retries the removal.
		if err := os.Chmod(u.dataDir, 0o700); err != nil { //nolint:gosec // a directory, writable again
			t.Fatal(err)
		}
		u.welcomed(t.Context(), log)
		if _, ok := readPending(t, u.dataDir); ok {
			t.Error("marker kept after a Welcome that could remove it")
		}
	})

	t.Run("nothing pending", func(t *testing.T) {
		t.Parallel()
		u := &upgrader{dataDir: t.TempDir(), noHub: time.Millisecond}
		end := u.watchWelcome(t.Context(), log, func(err error) { t.Errorf("stop(%v) with no upgrade pending", err) })
		time.Sleep(20 * time.Millisecond)
		end()
	})

	t.Run("stale rollback record", func(t *testing.T) {
		t.Parallel()
		record := func(t *testing.T, dataDir, v string) string {
			t.Helper()
			path := filepath.Join(dataDir, upgradeRolledBackFile)
			if err := os.WriteFile(path, []byte(v+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}
		for _, tt := range []struct {
			name    string
			current string
			pending bool
		}{
			// A binary from before the record existed never reported it,
			// and was upgraded since: the new one does not report it.
			{name: "an upgrade pending", current: "v1.2.4", pending: true},
			{name: "no newer than the version running", current: "v1.2.3"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				u, _ := setup(t)
				u.current = tt.current
				if !tt.pending {
					_ = os.Remove(filepath.Join(u.dataDir, upgradePendingFile))
				}
				path := record(t, u.dataDir, "v1.2.3")
				if err := u.started(t.Context(), log); err != nil {
					t.Fatal(err)
				}
				h := &agentv1.Hello{}
				u.hello(h)
				if h.GetRolledBackFrom() != "" {
					t.Errorf("Hello.rolled_back_from = %q, want none", h.GetRolledBackFrom())
				}
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("stale record kept: %v", err)
				}
			})
		}
	})

	t.Run("unreadable marker", func(t *testing.T) {
		t.Parallel()
		u, exe := setup(t)
		if err := os.WriteFile(filepath.Join(u.dataDir, upgradePendingFile), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := u.started(t.Context(), log); err != nil {
			t.Fatal(err)
		}
		if _, ok := readPending(t, u.dataDir); ok {
			t.Error("unreadable marker kept")
		}
		if got := readFile(t, exe); got != "new" {
			t.Errorf("executable = %q, want it kept", got)
		}
	})
}

// assertRollbackReported checks that u, the binary a rollback put back,
// tells the hub it was rolled back from from until a Welcome, and then no
// more.
func assertRollbackReported(t *testing.T, u *upgrader, from string) {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	h := &agentv1.Hello{}
	u.hello(h)
	if h.GetRolledBackFrom() != from {
		t.Fatalf("Hello.rolled_back_from = %q, want %q", h.GetRolledBackFrom(), from)
	}
	// Until a hub welcomes it, every Hello says it, a restart's too.
	again := &upgrader{exe: u.exe, dataDir: u.dataDir}
	if err := again.started(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	h = &agentv1.Hello{}
	again.hello(h)
	if h.GetRolledBackFrom() != from {
		t.Errorf("Hello.rolled_back_from after a restart = %q, want %q", h.GetRolledBackFrom(), from)
	}
	again.welcomed(t.Context(), log)
	h = &agentv1.Hello{}
	again.hello(h)
	if h.GetRolledBackFrom() != "" {
		t.Errorf("Hello.rolled_back_from after a Welcome = %q, want none", h.GetRolledBackFrom())
	}
	if _, err := os.Stat(filepath.Join(u.dataDir, upgradeRolledBackFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("rollback record kept after a Welcome: %v", err)
	}
}

// TestRunCountsStartsFirst checks that Run counts the start of an upgraded
// agent before anything else can fail, its identity included: a binary that
// cannot even load it is rolled back too.
func TestRunCountsStartsFirst(t *testing.T) {
	t.Parallel()
	exe := filepath.Join(t.TempDir(), "hearth")
	for path, body := range map[string]string{exe: "new", exe + ".prev": "old"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dataDir := t.TempDir() // no identity in it
	if err := writePending(dataDir, pendingUpgrade{From: "v1.0.0", To: "v1.2.3"}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{DataDir: dataDir, Log: slog.New(slog.DiscardHandler), upgrader: &upgrader{exe: exe, dataDir: dataDir}}
	for i := 1; i <= maxUpgradeStarts; i++ {
		if err := Run(t.Context(), cfg); err == nil || errors.Is(err, ErrUpgraded) {
			t.Fatalf("Run %d without an identity = %v, want its error", i, err)
		}
	}
	if err := Run(t.Context(), cfg); !errors.Is(err, ErrUpgraded) {
		t.Fatalf("Run %d = %v, want the rollback", maxUpgradeStarts+1, err)
	}
	if got := readFile(t, exe); got != "old" {
		t.Errorf("executable = %q, want the previous one back", got)
	}
}

func TestSelfUpgradeRefusal(t *testing.T) {
	t.Parallel()
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	tests := []struct {
		goos   string
		locked bool
		env    func(string) string
		want   string
	}{
		{"linux", false, env(), ""},
		{"darwin", false, env(), ""},
		{"linux", false, env("KUBERNETES_SERVICE_HOST", "10.96.0.1"), "Kubernetes"},
		{"linux", false, env("HEARTH_NO_SELF_UPGRADE", "1"), "turned off"},
		{"linux", true, env(), "--local-ceiling"},
		{"windows", false, env(), "Windows"},
		{"android", false, env(), "android"},
	}
	for _, tt := range tests {
		got := selfUpgradeRefusal(tt.goos, tt.locked, tt.env)
		if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
			t.Errorf("selfUpgradeRefusal(%s, %v) = %q, want %q", tt.goos, tt.locked, got, tt.want)
		}
	}
}

func TestReleaseTarget(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ goos, goarch, goarm, want string }{
		{"linux", "amd64", "", "linux_amd64"},
		{"linux", "arm64", "", "linux_arm64"},
		{"linux", "arm", "7", "linux_armv7"},
		{"darwin", "arm64", "", "darwin_arm64"},
	} {
		if got := releaseTarget(tt.goos, tt.goarch, tt.goarm); got != tt.want {
			t.Errorf("releaseTarget(%s, %s, %s) = %s, want %s", tt.goos, tt.goarch, tt.goarm, got, tt.want)
		}
	}
}

func TestUpgraderHello(t *testing.T) {
	t.Parallel()
	u := &upgrader{target: "linux_amd64"}
	h := &agentv1.Hello{}
	u.hello(h)
	if h.GetReleaseTarget() != "linux_amd64" || h.GetNoSelfUpgrade() != "" {
		t.Errorf("hello of an upgrader = %v", h)
	}
	u.refusal = "in a pod"
	h = &agentv1.Hello{}
	u.hello(h)
	if h.GetReleaseTarget() != "" || h.GetNoSelfUpgrade() != "in a pod" {
		t.Errorf("hello of a refusing upgrader = %v", h)
	}
}
