// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// A plugin's manifest, its program and the files its args name decide what
// the hub runs as its own user. On Unix each must be owned by the hub's user
// or root and writable by no one else, and so must every directory above it
// (a root-owned sticky directory, such as /tmp, is allowed): whoever could
// change one of them could run code as the hub. See checkInfo.

// checkDirs checks dir and every directory above it. dir has no symlinks.
func checkDirs(dir string) error {
	for {
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if err := checkInfo(dir, fi); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// openTrusted resolves the symlinks of path, checks the regular file it
// names and the directories above it, and opens it. The opened file is
// checked again, and must be the one checked by path, so that a swap in
// between is caught. It returns the file, which the caller closes, and its
// resolved path.
func openTrusted(path string) (*os.File, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, "", err
	}
	if err := checkDirs(filepath.Dir(resolved)); err != nil {
		return nil, "", err
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return nil, "", err
	}
	if !fi.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%s is not a regular file", resolved)
	}
	if err := checkInfo(resolved, fi); err != nil {
		return nil, "", err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, "", err
	}
	ofi, err := f.Stat()
	if err == nil && !os.SameFile(fi, ofi) {
		err = fmt.Errorf("%s changed while it was checked", resolved)
	}
	if err == nil {
		err = checkInfo(resolved, ofi)
	}
	if err != nil {
		_ = f.Close()
		return nil, "", err
	}
	return f, resolved, nil
}

// trustedProgram checks the program to run and the files of the plugin's
// directory its args name, and returns the program's resolved path and SHA-256.
func (p *plugin) trustedProgram(path string) (string, string, error) {
	f, resolved, err := openTrusted(path)
	if err != nil {
		return "", "", fmt.Errorf("plugin %s: %w", p.m.Name, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", fmt.Errorf("plugin %s: read %s: %w", p.m.Name, resolved, err)
	}
	dir, err := filepath.EvalSymlinks(p.m.Dir)
	if err == nil {
		err = checkDirs(dir)
	}
	if err != nil {
		return "", "", fmt.Errorf("plugin %s: %w", p.m.Name, err)
	}
	// A script the program runs, such as plugin.py, is code as well.
	for _, a := range p.m.Args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		file := a
		if !filepath.IsAbs(file) {
			file = filepath.Join(p.m.Dir, file)
		}
		if fi, err := os.Stat(file); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		af, _, err := openTrusted(file)
		if err != nil {
			return "", "", fmt.Errorf("plugin %s: %w", p.m.Name, err)
		}
		_ = af.Close()
	}
	return resolved, hex.EncodeToString(h.Sum(nil)), nil
}
