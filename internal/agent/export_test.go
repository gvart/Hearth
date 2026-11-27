// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// WithNetEdgesReader makes Run read network edges with read instead of the
// platform's reader, so tests on any OS see what is sent.
func WithNetEdgesReader(cfg Config, read func() (*agentv1.NetEdges, error)) Config {
	cfg.readNetEdges = read
	return cfg
}

// WithSelfUpgrade makes Run upgrade the executable exe from the releases at
// base, whatever the environment of the test says (a CI runner in a
// Kubernetes pod).
func WithSelfUpgrade(cfg Config, exe, base string) Config {
	cfg.upgrader = newUpgrader(exe, cfg.DataDir, cfg.Version, cfg.LocalCeiling, func(string) string { return "" })
	cfg.upgrader.base = base
	return cfg
}

// ReleaseServer serves the release version, for this platform, whose hearth
// prints version, and returns its base URL.
func ReleaseServer(t *testing.T, version string) string {
	archive, sum := fakeRelease(t, "hearth", version)
	return releaseServer(t, releaseFor(version, releaseTarget(runtime.GOOS, runtime.GOARCH, goarm()), archive, sum))
}

// UpgradePending reports whether dataDir holds an upgrade no hub welcomed
// yet.
func UpgradePending(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, upgradePendingFile))
	return err == nil
}
