// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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
	cfg.upgrader = newUpgrader(exe, cfg.DataDir, cfg.Version, "", cfg.LocalCeiling, func(string) string { return "" })
	cfg.upgrader.base, cfg.upgrader.pubKey = base, testReleasePublicKey()
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

// WithNoHubRollback makes the upgraded agent of cfg (WithSelfUpgrade) roll
// back after d without a Welcome.
func WithNoHubRollback(cfg Config, d time.Duration) Config {
	cfg.upgrader.noHub = d
	return cfg
}

// PendUpgrade marks dataDir as holding an upgrade from from to to that no
// hub welcomed yet.
func PendUpgrade(t *testing.T, dataDir, from, to string) {
	t.Helper()
	if err := writePending(dataDir, pendingUpgrade{From: from, To: to}); err != nil {
		t.Fatal(err)
	}
}

// RollbackRecorded reports whether dataDir holds a rollback no hub was told
// of yet.
func RollbackRecorded(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, upgradeRolledBackFile))
	return err == nil
}
