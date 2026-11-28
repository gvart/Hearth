// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/release"
)

// A plugin registry (#75) is an index, a JSON file anyone may host (an
// http(s) URL, or a file for an air-gapped lab), that lists WASM plugins:
// what each is, where its module is, the module's SHA-256, and the manifest
// the hub runs it with, its host grants included. The index is signed with
// Ed25519, its detached signature at <index>.sig (the base64 of the
// signature over the index's exact bytes, as a release's checksums.txt.sig).
// The hub trusts only the index keys its operator configures: none by
// default, and the registry is off. Every plugin installed from one runs
// with the manifest the signed index gave it, never with anything the
// module or the index's host says otherwise.

// IndexFormat is the version of the index format this hub reads.
const IndexFormat = 1

// IndexSigSuffix is appended to an index's location to name its signature.
const IndexSigSuffix = ".sig"

const (
	// maxIndex bounds an index, and maxIndexSig its signature.
	maxIndex    = 4 << 20
	maxIndexSig = 1 << 10
	// maxIndexText bounds an entry's free text fields.
	maxIndexText = 512
	// maxIndexEntries bounds the entries of an index.
	maxIndexEntries = 4096
	// registryTimeout bounds a fetch from a registry.
	registryTimeout = 2 * time.Minute
)

// Errors of the registry.
var (
	// ErrIndexSignature is an index whose signature is missing, malformed,
	// or does not verify with any trusted key.
	ErrIndexSignature = errors.New("the plugin index's signature does not verify")
	// ErrRegistryOff is a registry action on a hub with no index configured.
	ErrRegistryOff = errors.New("no plugin index is configured")
	// ErrNotInIndex is a plugin, or a version of one, the index does not list.
	ErrNotInIndex = errors.New("the plugin index does not list it")
	// ErrDowngrade is an update to an older version than the installed one.
	ErrDowngrade = errors.New("that version is older than the one installed")
	// ErrUpToDate is an update to the version installed.
	ErrUpToDate = errors.New("that version is installed already")
	// ErrIndexChanged is an install or update whose entry is not the one
	// the caller confirmed: the index changed meanwhile.
	ErrIndexChanged = errors.New("the plugin index changed: review the plugin again")
	// ErrModuleChanged is an update to the version installed with another
	// module: only a changed index offers one.
	ErrModuleChanged = errors.New("the index offers another module for the version installed")
	// ErrInstalled is an install of a plugin installed already.
	ErrInstalled = errors.New("the plugin is installed already")
	// ErrNotInstalled is an update or a removal of a plugin not installed.
	ErrNotInstalled = errors.New("the plugin is not installed")
)

// Index is a plugin registry's index.
type Index struct {
	// Format is IndexFormat.
	Format  int          `json:"format"`
	Plugins []IndexEntry `json:"plugins"`
}

// IndexEntry is one version of one plugin in an index: what the operator
// is shown before installing it, and the manifest it runs with.
type IndexEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Author      string `json:"author,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
	License     string `json:"license,omitempty"`
	// Runtime is RuntimeWasm: the registry installs only sandboxed plugins.
	Runtime string `json:"runtime"`
	// URL is the module's location: an http(s) URL, or a path relative to
	// the index's.
	URL string `json:"url"`
	// SHA256 pins the module, in lower-case hex.
	SHA256 string `json:"sha256"`
	// The rest is the manifest the plugin runs with.
	Memory       int           `json:"memory,omitempty"`
	Args         []string      `json:"args,omitempty"`
	Capabilities []string      `json:"capabilities"`
	Commands     []CommandSpec `json:"commands,omitempty"`
	Host         HostGrants    `json:"host"`
}

// moduleFile and manifestFile are an installed release's files.
const (
	moduleFile   = "plugin.wasm"
	manifestFile = "plugin.yaml"
)

// Manifest is the manifest e runs with once installed in dir.
func (e IndexEntry) Manifest(dir string) Manifest {
	return Manifest{
		Protocol: ProtocolVersion, Name: e.Name, Version: e.Version, Runtime: RuntimeWasm,
		Command: "./" + moduleFile, SHA256: e.SHA256, Memory: e.Memory, Args: e.Args,
		Capabilities: e.Capabilities, Commands: e.Commands, Host: e.Host, Dir: dir,
	}
}

// Digest names everything e says, its manifest and host grants included:
// the SHA-256 of its JSON, in hex. A caller that reviewed an entry confirms
// it by its digest, so that an index re-signed meanwhile with the same
// module but wider grants is refused.
func (e IndexEntry) Digest() string {
	b, _ := json.Marshal(e) // an IndexEntry always marshals
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// MemoryMiB is e's memory cap, in MiB.
func (e IndexEntry) MemoryMiB() int { return e.Manifest("").wasmMemory() }

// Validate checks e.
func (e IndexEntry) Validate() error {
	var errs []error
	if e.Runtime != RuntimeWasm {
		errs = append(errs, fmt.Errorf("runtime %q: a registry installs wasm plugins only", e.Runtime))
	}
	if !ValidVersion(e.Version) {
		errs = append(errs, fmt.Errorf("version %q: want a semantic version, such as 1.2.0", e.Version))
	}
	if !ValidSHA256(e.SHA256) {
		errs = append(errs, errors.New("sha256: want 64 lower-case hex digits"))
	}
	if err := checkModuleURL(e.URL); err != nil {
		errs = append(errs, err)
	}
	if e.Homepage != "" {
		if u, err := url.Parse(e.Homepage); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, errors.New("homepage: want an http(s) URL"))
		}
	}
	for k, v := range map[string]string{"description": e.Description, "author": e.Author, "homepage": e.Homepage, "license": e.License} {
		if len(v) > maxIndexText {
			errs = append(errs, fmt.Errorf("%s: longer than %d bytes", k, maxIndexText))
		}
	}
	if err := e.Manifest("").Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("plugin %s %s: %w", e.Name, e.Version, err)
	}
	return nil
}

// checkModuleURL checks a module's location: an http(s) URL without
// credentials, or a relative path that stays below the index's directory.
func checkModuleURL(s string) error {
	u, err := url.Parse(s)
	switch {
	case s == "" || err != nil:
		return errors.New("url: want the module's http(s) URL, or its path relative to the index")
	case u.User != nil:
		return errors.New("url: may not carry credentials")
	case u.Scheme == "https" || u.Scheme == "http":
		if u.Host == "" {
			return errors.New("url: names no host")
		}
		return nil
	case u.Scheme != "" || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(s, `?#\`):
		return errors.New("url: want an http(s) URL or a plain relative path")
	case path.IsAbs(s) || slices.Contains(strings.Split(s, "/"), ".."):
		return errors.New("url: a relative path may not climb above the index")
	}
	return nil
}

// ValidVersion reports whether v is a semantic version, with or without a
// leading v: 1.2.0, v1.2.0-rc.1.
func ValidVersion(v string) bool { return release.Tag.MatchString("v" + strings.TrimPrefix(v, "v")) }

// CompareVersions compares two semantic versions: -1, 0 or 1.
func CompareVersions(a, b string) int {
	return release.Compare("v"+strings.TrimPrefix(a, "v"), "v"+strings.TrimPrefix(b, "v"))
}

// ParseIndex parses and checks an index. Verify its signature first.
func ParseIndex(b []byte) (*Index, error) {
	var idx Index
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&idx); err != nil {
		return nil, fmt.Errorf("plugin index: %w", err)
	}
	if idx.Format != IndexFormat {
		return nil, fmt.Errorf("plugin index: format %d, this hub reads %d", idx.Format, IndexFormat)
	}
	if len(idx.Plugins) > maxIndexEntries {
		return nil, fmt.Errorf("plugin index: more than %d entries", maxIndexEntries)
	}
	seen := map[string]bool{}
	var errs []error
	for _, e := range idx.Plugins {
		if err := e.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		key := e.Name + "\x00" + strings.TrimPrefix(e.Version, "v")
		if seen[key] {
			errs = append(errs, fmt.Errorf("plugin %s %s: listed twice", e.Name, e.Version))
		}
		seen[key] = true
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("plugin index: %w", err)
	}
	return &idx, nil
}

// Versions are the entries of plugin name, newest first.
func (idx *Index) Versions(name string) []IndexEntry {
	var out []IndexEntry
	for _, e := range idx.Plugins {
		if e.Name == name {
			out = append(out, e)
		}
	}
	slices.SortStableFunc(out, func(a, b IndexEntry) int { return CompareVersions(b.Version, a.Version) })
	return out
}

// Latest is the newest entry of plugin name.
func (idx *Index) Latest(name string) (IndexEntry, bool) {
	v := idx.Versions(name)
	if len(v) == 0 {
		return IndexEntry{}, false
	}
	return v[0], true
}

// Entry is version of plugin name; an empty version is the newest.
func (idx *Index) Entry(name, version string) (IndexEntry, error) {
	if version == "" {
		if e, ok := idx.Latest(name); ok {
			return e, nil
		}
		return IndexEntry{}, fmt.Errorf("plugin %s: %w", name, ErrNotInIndex)
	}
	for _, e := range idx.Versions(name) {
		if CompareVersions(e.Version, version) == 0 {
			return e, nil
		}
	}
	return IndexEntry{}, fmt.Errorf("plugin %s %s: %w", name, version, ErrNotInIndex)
}

// Newest are the newest entries of every plugin, by name.
func (idx *Index) Newest() []IndexEntry {
	var names []string
	for _, e := range idx.Plugins {
		if !slices.Contains(names, e.Name) {
			names = append(names, e.Name)
		}
	}
	slices.Sort(names)
	out := make([]IndexEntry, 0, len(names))
	for _, n := range names {
		e, _ := idx.Latest(n)
		out = append(out, e)
	}
	return out
}

// ParseIndexKey decodes the base64 of a raw Ed25519 public key that signs
// indexes.
func ParseIndexKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("a plugin index key is the base64 of a 32-byte Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// ParseIndexSeed decodes the base64 of a 32-byte Ed25519 seed, an index
// signing key. The error never quotes s.
func ParseIndexSeed(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("the index signing key is not the base64 of a 32-byte Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// KeyID is a short name of an index key, for display: the first 16 hex
// digits of its SHA-256.
func KeyID(k ed25519.PublicKey) string {
	s := sha256.Sum256(k)
	return hex.EncodeToString(s[:8])
}

// SignIndex is the content of <index>.sig for index: the base64 of key's
// signature over its exact bytes, and a newline.
func SignIndex(key ed25519.PrivateKey, index []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, index)) + "\n")
}

// VerifyIndex checks sig, the content of <index>.sig, against index and
// each of keys, and returns the key that verifies it.
func VerifyIndex(keys []ed25519.PublicKey, index, sig []byte) (ed25519.PublicKey, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no index key is trusted", ErrIndexSignature)
	}
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(s) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: the signature is missing or malformed", ErrIndexSignature)
	}
	for _, k := range keys {
		if ed25519.Verify(k, index, s) {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w with any trusted key", ErrIndexSignature)
}

// Registry is a signed plugin index and the keys it is checked with.
type Registry struct {
	// Source is the index's location: an http(s) URL or a file path.
	Source string
	Keys   []ed25519.PublicKey
	// Client fetches over http(s); default: one that takes no redirect to
	// another scheme and times out.
	Client *http.Client
}

// NewRegistry checks source and keys. An empty source with no keys is no
// registry: nil, nil. A source needs at least one key, and keys a source.
func NewRegistry(source string, keys []string) (*Registry, error) {
	source = strings.TrimSpace(source)
	if source == "" && len(keys) == 0 {
		return nil, nil
	}
	if source == "" {
		return nil, errors.New("--plugin-index-key needs --plugin-index, the index it verifies")
	}
	if len(keys) == 0 {
		return nil, errors.New("--plugin-index needs --plugin-index-key: the hub trusts no index without a key")
	}
	if err := CheckIndexSource(source); err != nil {
		return nil, err
	}
	r := &Registry{Source: source}
	for _, s := range keys {
		k, err := ParseIndexKey(s)
		if err != nil {
			return nil, err
		}
		r.Keys = append(r.Keys, k)
	}
	return r, nil
}

// CheckIndexSource checks an index's location: an http(s) URL without
// credentials, a query or a fragment (it is shown and audited), or a file
// path.
func CheckIndexSource(s string) error {
	if !isURL(s) {
		return nil
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return errors.New("the plugin index is not a URL")
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("the plugin index must be an http(s) URL or a file path")
	case u.Host == "":
		return errors.New("the plugin index URL names no host")
	case u.User != nil:
		return errors.New("the plugin index URL may not carry credentials: they would show in the audit log")
	case u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(s, "?#"):
		return errors.New("the plugin index URL may not have a query or a fragment")
	}
	return nil
}

// isURL reports whether s names a URL rather than a file.
func isURL(s string) bool { return strings.Contains(s, "://") }

func (r *Registry) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{
		Timeout: registryTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return errors.New("redirect to another scheme")
			}
			return nil
		},
	}
}

// Fetch reads the index and its signature, checks the signature over the
// exact bytes read with the trusted keys, and only then parses it.
func (r *Registry) Fetch(ctx context.Context) (*Index, error) {
	if r == nil {
		return nil, ErrRegistryOff
	}
	b, err := r.read(ctx, r.Source, maxIndex)
	if err != nil {
		return nil, fmt.Errorf("read the plugin index: %w", err)
	}
	sig, err := r.read(ctx, r.Source+IndexSigSuffix, maxIndexSig)
	if err != nil {
		return nil, fmt.Errorf("%w: read its signature: %w", ErrIndexSignature, err)
	}
	if _, err := VerifyIndex(r.Keys, b, sig); err != nil {
		return nil, err
	}
	return ParseIndex(b)
}

// moduleLocation resolves an entry's url against the index's location.
func (r *Registry) moduleLocation(e IndexEntry) (string, error) {
	if err := checkModuleURL(e.URL); err != nil {
		return "", err
	}
	if isURL(e.URL) {
		return e.URL, nil
	}
	if !isURL(r.Source) {
		return filepath.Join(filepath.Dir(r.Source), filepath.FromSlash(e.URL)), nil
	}
	base, err := url.Parse(r.Source)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(e.URL)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

// Download fetches e's module and checks it against the SHA-256 the index
// pins: a module that differs is refused.
func (r *Registry) Download(ctx context.Context, e IndexEntry) ([]byte, error) {
	loc, err := r.moduleLocation(e)
	if err != nil {
		return nil, fmt.Errorf("plugin %s %s: %w", e.Name, e.Version, err)
	}
	b, err := r.read(ctx, loc, MaxProgramSize)
	if err != nil {
		return nil, fmt.Errorf("download plugin %s %s: %w", e.Name, e.Version, err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != e.SHA256 {
		return nil, fmt.Errorf("plugin %s %s: the module's SHA-256 is %s, the index pins %s: %w",
			e.Name, e.Version, got, e.SHA256, ErrPinMismatch)
	}
	return b, nil
}

// read reads at most limit bytes from loc, a URL or a file.
func (r *Registry) read(ctx context.Context, loc string, limit int64) ([]byte, error) {
	var rc io.ReadCloser
	if isURL(loc) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
		if err != nil {
			return nil, err
		}
		resp, err := r.client().Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%s: %s", redact(loc), resp.Status)
		}
		rc = resp.Body
	} else {
		f, err := os.Open(loc)
		if err != nil {
			return nil, err
		}
		rc = f
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", redact(loc), limit)
	}
	return b, nil
}

// redact is a URL as shown in errors: without credentials or a query.
func redact(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return "the URL"
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}
