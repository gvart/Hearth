// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"slices"

	"github.com/gvart/hearth/internal/automation"
)

// ConfigFileDigest returns a SHA-256 digest, in hex, of the file at path and
// of extra, the settings given on the command line that act like part of the
// file, in any order. A missing file digests like an empty one, which both
// mean no configuration. It returns "" for a file it cannot read: the other
// hubs then show this item as unknown.
func ConfigFileDigest(path string, extra ...string) string {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	sum := sha256.Sum256(b)
	h := sha256.New()
	_, _ = h.Write(sum[:])
	sorted := slices.Sorted(slices.Values(extra))
	for _, s := range slices.Compact(sorted) {
		_, _ = h.Write(append([]byte(s), 0))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FileConfigSource reports the digests of the policy and notification files as
// the hub loaded them, and of the automations and runbooks directories as they
// are now: followers load the automations only when they take over, and the
// runbooks are read when a run starts, so their files are what counts.
func FileConfigSource(policyDigest, notifyDigest, automationsDir, runbooksDir string) ConfigSource {
	return func() map[string]string {
		out := map[string]string{}
		if policyDigest != "" {
			out[ConfigPolicy] = policyDigest
		}
		if notifyDigest != "" {
			out[ConfigNotify] = notifyDigest
		}
		if d, err := automation.DirDigest(automationsDir); err == nil {
			out[ConfigAutomations] = d
		}
		// Runbooks load from the same kind of directory, so they digest alike.
		if d, err := automation.DirDigest(runbooksDir); err == nil {
			out[ConfigRunbooks] = d
		}
		return out
	}
}
