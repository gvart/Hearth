// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

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

// testUpgrader is an upgrader of a fake executable in a temporary
// directory, holding "old".
func testUpgrader(t *testing.T) (*upgrader, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake release's hearth is a shell script")
	}
	exe := filepath.Join(t.TempDir(), "hearth")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newUpgrader(exe, func(string) string { return "" })
	return u, exe
}

func serve(t *testing.T, body []byte, chunked bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if chunked {
			// No Content-Length: the cap must hold while reading.
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1.2.3/hearth_1.2.3_linux_amd64.tar.gz"
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

func TestUpgradeReplacesTheBinary(t *testing.T) {
	t.Parallel()
	u, exe := testUpgrader(t)
	archive, sum := fakeRelease(t, "hearth", "v1.2.3")
	res := u.upgrade(t.Context(), &agentv1.UpgradeRequest{Id: "u1", Version: "v1.2.3", Url: serve(t, archive, false), Sha256: sum})
	if !res.GetOk() || res.GetVersion() != "v1.2.3" || res.GetId() != "u1" {
		t.Fatalf("upgrade = %v, want ok with v1.2.3", res)
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
	// A second upgrade replaces the backup.
	archive, sum = fakeRelease(t, "./hearth", "v1.2.4")
	res = u.upgrade(t.Context(), &agentv1.UpgradeRequest{Version: "v1.2.4", Url: serve(t, archive, false), Sha256: sum})
	if !res.GetOk() {
		t.Fatalf("second upgrade = %v", res)
	}
	if got := readFile(t, exe+".prev"); !strings.Contains(got, "hearth v1.2.3") {
		t.Errorf("backup after the second upgrade = %q, want v1.2.3", got)
	}
}

// TestUpgradeRefused checks that every failed check leaves the old binary
// as it was, and nothing next to it.
func TestUpgradeRefused(t *testing.T) {
	t.Parallel()
	archive, sum := fakeRelease(t, "hearth", "v1.2.3")
	noBinary, noBinarySum := fakeRelease(t, "hearth-other", "v1.2.3")
	other := strings.Repeat("0", 64)
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	tests := []struct {
		name    string
		req     *agentv1.UpgradeRequest
		setup   func(u *upgrader)
		denied  bool
		wantErr string
	}{
		{name: "sha256 mismatch", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: serve(t, archive, false), Sha256: other},
			wantErr: "checksum mismatch"},
		{name: "too large, by Content-Length", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: serve(t, archive, false), Sha256: sum},
			setup: func(u *upgrader) { u.maxArchive = 100 }, wantErr: "larger than"},
		{name: "too large, while reading", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: serve(t, archive, true), Sha256: sum},
			setup: func(u *upgrader) { u.maxArchive = 100 }, wantErr: "larger than"},
		{name: "binary too large", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: serve(t, archive, false), Sha256: sum},
			setup: func(u *upgrader) { u.maxBinary = 10 }, wantErr: "larger than"},
		{name: "no hearth in the archive", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: serve(t, noBinary, false), Sha256: noBinarySum},
			wantErr: "no hearth binary"},
		{name: "another version inside", req: &agentv1.UpgradeRequest{Version: "v1.2.4", Url: serve(t, archive, false), Sha256: sum},
			wantErr: "reports version"},
		{name: "not found", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: notFound.URL + "/hearth.tar.gz", Sha256: sum},
			wantErr: "404"},
		{name: "no sha256", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: serve(t, archive, false)}, denied: true, wantErr: "SHA-256"},
		{name: "no version", req: &agentv1.UpgradeRequest{Version: "latest", Url: serve(t, archive, false), Sha256: sum}, denied: true, wantErr: "version"},
		{name: "file URL", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: "file:///etc/passwd", Sha256: sum}, denied: true, wantErr: "URL"},
		{name: "kubernetes", req: &agentv1.UpgradeRequest{Version: "v1.2.3", Url: serve(t, archive, false), Sha256: sum},
			setup: func(u *upgrader) {
				u.refusal = selfUpgradeRefusal("linux", func(k string) string {
					if k == "KUBERNETES_SERVICE_HOST" {
						return "10.0.0.1"
					}
					return ""
				})
			}, denied: true, wantErr: "upgrade its image"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, exe := testUpgrader(t)
			if tt.setup != nil {
				tt.setup(u)
			}
			res := u.upgrade(t.Context(), tt.req)
			if res.GetOk() || res.GetDenied() != tt.denied || !strings.Contains(res.GetError(), tt.wantErr) {
				t.Fatalf("upgrade = %v, want denied=%v and an error with %q", res, tt.denied, tt.wantErr)
			}
			if got := readFile(t, exe); got != "old" {
				t.Errorf("executable = %q, want the old binary intact", got)
			}
			if l := leftovers(t, exe); len(l) != 0 {
				t.Errorf("files left next to the binary: %v", l)
			}
		})
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
		goos string
		env  func(string) string
		want string
	}{
		{"linux", env(), ""},
		{"darwin", env(), ""},
		{"linux", env("KUBERNETES_SERVICE_HOST", "10.96.0.1"), "Kubernetes"},
		{"linux", env("HEARTH_NO_SELF_UPGRADE", "1"), "turned off"},
		{"windows", env(), "Windows"},
		{"android", env(), "android"},
	}
	for _, tt := range tests {
		got := selfUpgradeRefusal(tt.goos, tt.env)
		if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
			t.Errorf("selfUpgradeRefusal(%s) = %q, want %q", tt.goos, got, tt.want)
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
