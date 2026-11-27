// SPDX-License-Identifier: AGPL-3.0-only

package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMirrorBase(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"https://mirror.lan/hearth/", "https://mirror.lan/hearth", true},
		{"https://mirror.lan:8443/releases", "https://mirror.lan:8443/releases", true},
		{"http://10.0.0.5:8000", "http://10.0.0.5:8000", true},
		{"", "", false},
		{"mirror.lan/hearth", "", false},
		{"ftp://mirror.lan/hearth", "", false},
		{"file:///srv/hearth", "", false},
		{"https://", "", false},
		{"https://user:secret@mirror.lan/hearth", "", false},
		{"https://mirror.lan/hearth?token=x", "", false},
		{"https://mirror.lan/hearth#x", "", false},
		{"https://mirror.lan/hearth?", "", false},
	} {
		got, err := MirrorBase(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("MirrorBase(%q) = %q, %v; want %q, ok %v", tc.in, got, err, tc.want, tc.ok)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("MirrorBase(%q) error quotes the credentials: %v", tc.in, err)
		}
	}
}

// fakeUpstream is a release tag served as GitHub does.
type fakeUpstream struct {
	tag       string
	assets    map[string][]byte
	checksums string // "" for one listing assets
	sig       []byte // nil for key's signature of checksums
	bundle    bool   // serve checksums.txt.sigstore.json
	corrupt   string // an asset served with other bytes
}

func (f *fakeUpstream) serve(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	if f.checksums == "" {
		for name, b := range f.assets {
			s := sha256.Sum256(b)
			f.checksums += hex.EncodeToString(s[:]) + "  " + name + "\n"
		}
	}
	if f.sig == nil {
		f.sig = Sign(key, []byte(f.checksums))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := strings.CutPrefix(r.URL.Path, "/"+f.tag+"/")
		switch {
		case !ok:
			http.NotFound(w, r)
		case name == ChecksumsFile:
			_, _ = w.Write([]byte(f.checksums))
		case name == ChecksumsFile+SignatureSuffix:
			_, _ = w.Write(f.sig)
		case name == ChecksumsFile+SigstoreSuffix && f.bundle:
			_, _ = w.Write([]byte(`{"bundle":true}`))
		case name == f.corrupt:
			_, _ = w.Write([]byte("not the asset"))
		case f.assets[name] != nil:
			_, _ = w.Write(f.assets[name])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestMirror(t *testing.T) {
	t.Parallel()
	pub, priv := testKeys(t)
	up := &fakeUpstream{tag: "v1.2.3", bundle: true, assets: map[string][]byte{
		"hearth_1.2.3_linux_arm64.tar.gz":  []byte("arm64 archive"),
		"hearth_1.2.3_darwin_arm64.tar.gz": []byte("darwin archive"),
	}}
	base := up.serve(t, priv)
	dir := t.TempDir()
	if err := Mirror(context.Background(), HTTPClient(), pub, base+"/", "v1.2.3", dir, func(string) {}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"hearth_1.2.3_linux_arm64.tar.gz":  "arm64 archive",
		"hearth_1.2.3_darwin_arm64.tar.gz": "darwin archive",
		ChecksumsFile:                      up.checksums,
		ChecksumsFile + SignatureSuffix:    string(up.sig),
		ChecksumsFile + SigstoreSuffix:     `{"bundle":true}`,
	} {
		b, err := os.ReadFile(filepath.Join(dir, "v1.2.3", name))
		if err != nil || string(b) != want {
			t.Errorf("%s = %q, %v; want %q", name, b, err, want)
		}
	}
	// A second run keeps what is there.
	var said []string
	if err := Mirror(context.Background(), HTTPClient(), pub, base, "v1.2.3", dir, func(s string) { said = append(said, s) }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(said, "\n"), "already mirrored") {
		t.Errorf("second run said %q, want assets kept", said)
	}
}

func TestMirrorRefused(t *testing.T) {
	t.Parallel()
	pub, priv := testKeys(t)
	_, other := testKeys(t)
	assets := map[string][]byte{"hearth_1.2.3_linux_arm64.tar.gz": []byte("archive")}
	for _, tc := range []struct {
		name string
		up   fakeUpstream
		tag  string
		want string
	}{
		{"not a tag", fakeUpstream{tag: "v1.2.3", assets: assets}, "../v1.2.3", "not a release tag"},
		{"no release", fakeUpstream{tag: "v9.9.9", assets: assets}, "v1.2.3", "is v1.2.3 a release?"},
		{"signed with another key", fakeUpstream{tag: "v1.2.3", assets: assets, sig: Sign(other, []byte("x"))}, "v1.2.3", "does not verify"},
		{"malformed signature", fakeUpstream{tag: "v1.2.3", assets: assets, sig: []byte("nope")}, "v1.2.3", "malformed"},
		{"path in a signed name", fakeUpstream{tag: "v1.2.3", assets: assets,
			checksums: strings.Repeat("a", 64) + "  ../../etc/passwd\n"}, "v1.2.3", "refused the asset name"},
		{"a signed name over checksums.txt", fakeUpstream{tag: "v1.2.3", assets: assets,
			checksums: strings.Repeat("a", 64) + "  checksums.txt.sig\n"}, "v1.2.3", "refused the asset name"},
		{"asset not matching its checksum", fakeUpstream{tag: "v1.2.3", assets: assets,
			corrupt: "hearth_1.2.3_linux_arm64.tar.gz"}, "v1.2.3", "checksum mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := tc.up.serve(t, priv)
			dir := t.TempDir()
			err := Mirror(context.Background(), HTTPClient(), pub, base, tc.tag, dir, func(string) {})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Mirror = %v, want an error with %q", err, tc.want)
			}
			// Nothing a mirror would serve is left: no checksums.txt, no asset.
			var left []string
			_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, _ error) error {
				if !d.IsDir() {
					left = append(left, p)
				}
				return nil
			})
			if len(left) != 0 {
				t.Errorf("left %v", left)
			}
		})
	}
}
