// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigFileDigest(t *testing.T) {
	dir := t.TempDir()
	a, b, empty := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "empty")
	writeConfig(t, a, "classes: {dangerous: deny}\n")
	writeConfig(t, b, "classes: {dangerous: allow}\n")
	writeConfig(t, empty, "")
	missing := filepath.Join(dir, "missing")

	if ConfigFileDigest(a) == ConfigFileDigest(b) {
		t.Error("different files digest alike")
	}
	if ConfigFileDigest(a) == "" {
		t.Error("a readable file has no digest")
	}
	if ConfigFileDigest(missing) != ConfigFileDigest(empty) {
		t.Error("a missing file and an empty one mean the same configuration")
	}
	if ConfigFileDigest(a) == ConfigFileDigest(missing) {
		t.Error("a file digests like no file")
	}
	if ConfigFileDigest(a, "backup") == ConfigFileDigest(a) {
		t.Error("a dangerous automation granted by flag does not change the digest")
	}
	if ConfigFileDigest(a, "x", "y", "x") != ConfigFileDigest(a, "y", "x") {
		t.Error("the digest depends on the order or repetition of the flags")
	}
	if got := ConfigFileDigest(dir); got != "" {
		t.Errorf("an unreadable path digests to %q, want none", got)
	}
}

// TestFileConfigSource: the two files count as the hub loaded them, the
// automations directory as it is now, and an unreadable item is left out.
func TestFileConfigSource(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeConfig(t, policyFile, "classes: {dangerous: deny}\n")
	automations := filepath.Join(dir, "automations")
	loaded := ConfigFileDigest(policyFile)
	runbooks := filepath.Join(dir, ConfigRunbooks)
	src := FileConfigSource(loaded, "", automations, runbooks)

	before := src()
	if before[ConfigPolicy] != loaded {
		t.Errorf("policy digest = %q, want the loaded one", before[ConfigPolicy])
	}
	if _, ok := before[ConfigNotify]; ok {
		t.Error("an unreadable notify file reports a digest")
	}

	writeConfig(t, policyFile, "classes: {dangerous: allow}\n")
	writeConfig(t, filepath.Join(automations, "new.yaml"), "id: new\n")
	after := src()
	if after[ConfigPolicy] != loaded {
		t.Error("an edit the hub has not loaded changed the policy digest")
	}
	if after[ConfigAutomations] == before[ConfigAutomations] {
		t.Error("a new automation file did not change the digest")
	}
	if after[ConfigRunbooks] != before[ConfigRunbooks] {
		t.Error("an automation file changed the runbooks digest")
	}
	writeConfig(t, filepath.Join(runbooks, "new.yaml"), "id: new\n")
	if src()[ConfigRunbooks] == before[ConfigRunbooks] {
		t.Error("a new runbook file did not change the digest")
	}
}

// loadHubFiles points h at the configuration files in its data dir, as a hub
// does when it starts.
func loadHubFiles(h *testHub) {
	h.SetConfigSource(FileConfigSource(
		ConfigFileDigest(filepath.Join(h.dir, ConfigPolicy)),
		ConfigFileDigest(filepath.Join(h.dir, ConfigNotify)),
		filepath.Join(h.dir, ConfigAutomations),
		filepath.Join(h.dir, ConfigRunbooks),
	))
}

// TestConfigDriftFromRealFiles compares real files across three hubs, over the
// hubs' mTLS channel: each item differing on one hub, the two files noticed
// when the hub loads them again and the automations directory at once.
func TestConfigDriftFromRealFiles(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	for _, h := range hubs {
		writeConfig(t, filepath.Join(h.dir, ConfigPolicy), "classes: {dangerous: deny}\n")
		writeConfig(t, filepath.Join(h.dir, ConfigNotify), "channels: {}\n")
		writeConfig(t, filepath.Join(h.dir, ConfigAutomations, "a.yaml"), "id: a\n")
		writeConfig(t, filepath.Join(h.dir, ConfigRunbooks, "r1.yaml"), "id: r1\n")
		writeConfig(t, filepath.Join(h.dir, ConfigRunbooks, "r2.yaml"), "id: r2\n")
		loadHubFiles(h)
	}
	for _, item := range configItems {
		wantItem(t, itemOf(t, driftOf(t, hubs[0].testNode), item), DriftInSync, allThree, []string{})
	}

	n3 := hubs[2]
	split := [][]string{{"n1", "n2"}, {"n3"}}
	writeConfig(t, filepath.Join(n3.dir, ConfigAutomations, "b.yaml"), "id: b\n")
	wantItem(t, itemOf(t, driftOf(t, hubs[0].testNode), ConfigAutomations), DriftDiffers, split, []string{})

	writeConfig(t, filepath.Join(n3.dir, ConfigPolicy), "classes: {dangerous: allow}\n")
	writeConfig(t, filepath.Join(n3.dir, ConfigNotify), "channels: {phone: {type: ntfy}}\n")
	r := driftOf(t, hubs[0].testNode)
	wantItem(t, itemOf(t, r, ConfigPolicy), DriftInSync, allThree, []string{})
	wantItem(t, itemOf(t, r, ConfigNotify), DriftInSync, allThree, []string{})

	loadHubFiles(n3) // the restart that applies the edited files
	r = driftOf(t, hubs[0].testNode)
	wantItem(t, itemOf(t, r, ConfigPolicy), DriftDiffers, split, []string{})
	wantItem(t, itemOf(t, r, ConfigNotify), DriftDiffers, split, []string{})
}

// TestRunbookDriftFromRealFiles: hubs with identical runbooks do not warn, and
// a runbook that differs, one missing on a hub and an extra one on a hub each
// show up, without touching the other items.
func TestRunbookDriftFromRealFiles(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	for _, h := range hubs {
		writeConfig(t, filepath.Join(h.dir, ConfigRunbooks, "r1.yaml"), "id: r1\n")
		writeConfig(t, filepath.Join(h.dir, ConfigRunbooks, "r2.yaml"), "id: r2\n")
		loadHubFiles(h)
	}
	split := [][]string{{"n1", "n2"}, {"n3"}}
	check := func(t *testing.T, status string, groups [][]string) {
		t.Helper()
		for _, h := range hubs {
			r := driftOf(t, h.testNode)
			wantItem(t, itemOf(t, r, ConfigRunbooks), status, groups, []string{})
			wantItem(t, itemOf(t, r, ConfigAutomations), DriftInSync, allThree, []string{})
		}
	}
	check(t, DriftInSync, allThree)

	n3 := hubs[2]
	tests := []struct {
		name  string
		apply func()
		undo  func()
	}{
		{
			"differs",
			func() { writeConfig(t, filepath.Join(n3.dir, ConfigRunbooks, "r2.yaml"), "id: r2\nname: edited\n") },
			func() { writeConfig(t, filepath.Join(n3.dir, ConfigRunbooks, "r2.yaml"), "id: r2\n") },
		},
		{
			"missing",
			func() {
				if err := os.Remove(filepath.Join(n3.dir, ConfigRunbooks, "r2.yaml")); err != nil {
					t.Fatal(err)
				}
			},
			func() { writeConfig(t, filepath.Join(n3.dir, ConfigRunbooks, "r2.yaml"), "id: r2\n") },
		},
		{
			"extra",
			func() { writeConfig(t, filepath.Join(n3.dir, ConfigRunbooks, "r3.yml"), "id: r3\n") },
			func() {
				if err := os.Remove(filepath.Join(n3.dir, ConfigRunbooks, "r3.yml")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.apply()
			check(t, DriftDiffers, split)
			tc.undo()
			check(t, DriftInSync, allThree)
		})
	}

	// Files Hearth does not load as runbooks do not count.
	writeConfig(t, filepath.Join(n3.dir, ConfigRunbooks, ".hidden.yaml"), "id: h\n")
	writeConfig(t, filepath.Join(n3.dir, ConfigRunbooks, "notes.txt"), "x\n")
	check(t, DriftInSync, allThree)
}
