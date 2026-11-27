// SPDX-License-Identifier: AGPL-3.0-only

package release

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// A release mirror (#348) serves releases as GitHub does, under
// <base>/<tag>/<asset>: checksums.txt, its signatures (checksums.txt.sig,
// which agents check, and checksums.txt.sigstore.json, which install.sh
// checks with cosign) and the archives checksums.txt lists. An agent that
// cannot reach GitHub upgrades from one with --release-mirror; Mirror fills
// one.

// BaseURL is where releases are published, as <BaseURL>/<tag>/<asset>.
const BaseURL = "https://github.com/gvart/hearth/releases/download"

const (
	// ChecksumsFile is the asset listing the SHA-256 of a release's others.
	ChecksumsFile = "checksums.txt"
	// SigstoreSuffix is appended to checksums.txt to name its Sigstore bundle.
	SigstoreSuffix = ".sigstore.json"

	maxChecksums = 1 << 20
	maxSignature = 1 << 10
	maxSigstore  = 1 << 20
	maxAsset     = 256 << 20
	maxRedirects = 5
)

// MirrorBase checks s, the base URL of a release mirror, and returns it
// without a trailing slash. It must be http or https: the signature of
// checksums.txt, not the transport, is what makes a release trusted. It may
// not carry credentials, a query or a fragment: an agent reports the URLs
// it downloads from to its hub, which audits them.
func MirrorBase(s string) (string, error) {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return "", errors.New("the release mirror is not a URL")
	case u.Scheme != "https" && u.Scheme != "http":
		return "", errors.New("the release mirror must be an http:// or https:// URL")
	case u.Host == "":
		return "", errors.New("the release mirror URL names no host")
	case u.User != nil:
		return "", errors.New("the release mirror URL may not carry credentials: they would show in the hub's audit log")
	case u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(s, "?#"):
		return "", errors.New("the release mirror URL may not have a query or a fragment")
	}
	return strings.TrimRight(s, "/"), nil
}

// Mirror copies release tag from base (BaseURL, or another mirror) into
// dir/<tag>/, so that dir served over HTTP is a release mirror. It checks
// checksums.txt against its signature with key first, then each asset it
// lists against its SHA-256, and writes checksums.txt and its signatures
// last: a mirror missing them is incomplete, never wrong. An asset already
// there with the right SHA-256 is kept. say reports progress.
func Mirror(ctx context.Context, client *http.Client, key ed25519.PublicKey, base, tag, dir string, say func(string)) error {
	if !Tag.MatchString(tag) {
		return fmt.Errorf("%q is not a release tag (vX.Y.Z)", tag)
	}
	src := strings.TrimRight(base, "/") + "/" + tag
	sums, err := fetch(ctx, client, src+"/"+ChecksumsFile, maxChecksums)
	if err != nil {
		return fmt.Errorf("%w (is %s a release?)", err, tag)
	}
	sig, err := fetch(ctx, client, src+"/"+ChecksumsFile+SignatureSuffix, maxSignature)
	if err != nil {
		return fmt.Errorf("%s is not signed, so it is not mirrored: %w", tag, err)
	}
	if err := Verify(key, sums, sig); err != nil {
		return fmt.Errorf("%s/%s: %w; nothing was mirrored", src, ChecksumsFile, err)
	}
	say("checksums.txt of " + tag + " is signed with the Hearth release key")
	assets, err := parseChecksums(sums)
	if err != nil {
		return fmt.Errorf("%s/%s: %w", src, ChecksumsFile, err)
	}
	out := filepath.Join(dir, tag)
	if err := os.MkdirAll(out, 0o755); err != nil { //nolint:gosec // a web server serves the mirror
		return fmt.Errorf("create %s: %w", out, err)
	}
	for _, a := range assets {
		path := filepath.Join(out, a.name)
		if hasSum(path, a.sum) {
			say(a.name + " is already mirrored")
			continue
		}
		say("downloading " + a.name)
		if err := download(ctx, client, src+"/"+a.name, a.sum, path); err != nil {
			return err
		}
	}
	// install.sh checks the Sigstore bundle when cosign is installed, and
	// refuses a release without one; older releases may have none.
	bundle, err := fetch(ctx, client, src+"/"+ChecksumsFile+SigstoreSuffix, maxSigstore)
	if err != nil {
		say("no " + ChecksumsFile + SigstoreSuffix + " (" + err.Error() + "): install.sh with cosign installed will refuse this release")
	} else if err := writeFile(filepath.Join(out, ChecksumsFile+SigstoreSuffix), bundle); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(out, ChecksumsFile+SignatureSuffix), sig); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(out, ChecksumsFile), sums); err != nil {
		return err
	}
	say(fmt.Sprintf("mirrored %s: %d assets in %s", tag, len(assets), out))
	return nil
}

// HTTPClient is a client for Mirror: it follows https redirects only, as
// GitHub sends release assets on to its object storage.
func HTTPClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refused a redirect to %s: only https", req.URL.Redacted())
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("more than %d redirects", maxRedirects)
		}
		return nil
	}}
}

type asset struct{ name, sum string }

// parseChecksums reads the assets checksums.txt lists. A name that is not a
// plain file name is refused, signed or not.
func parseChecksums(b []byte) ([]asset, error) {
	var out []asset
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("malformed line %q", sc.Text())
		}
		name := strings.TrimPrefix(f[1], "*")
		if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") ||
			name == ChecksumsFile || strings.HasPrefix(name, ChecksumsFile+".") {
			return nil, fmt.Errorf("refused the asset name %q", name)
		}
		if s, err := hex.DecodeString(f[0]); err != nil || len(s) != sha256.Size {
			return nil, fmt.Errorf("no valid SHA-256 for %s", name)
		}
		out = append(out, asset{name: name, sum: strings.ToLower(f[0])})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("lists no asset")
	}
	return out, nil
}

// hasSum says whether the file at path exists with SHA-256 sum.
func hasSum(path, sum string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == sum
}

// get fetches url, answering an error unless the server says 200 OK.
func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("download %s: the server answered %s", url, resp.Status)
	}
	return resp, nil
}

// fetch reads the whole body at url, refusing one over limit bytes.
func fetch(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	resp, err := get(ctx, client, url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes: refused", url, limit)
	}
	return b, nil
}

// download writes the asset at url to path once its SHA-256 is sum, through
// a temporary file next to it.
func download(ctx context.Context, client *http.Client, url, sum, path string) error {
	resp, err := get(ctx, client, url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mirror-*")
	if err != nil {
		return fmt.Errorf("write next to %s: %w", path, err)
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxAsset+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if n > maxAsset {
		return fmt.Errorf("%s is larger than %d MiB: refused", url, maxAsset>>20)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return fmt.Errorf("checksum mismatch for %s: its SHA-256 is %s, checksums.txt says %s", url, got, sum)
	}
	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeFile writes b to path through a temporary file next to it.
func writeFile(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mirror-*")
	if err != nil {
		return fmt.Errorf("write next to %s: %w", path, err)
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
