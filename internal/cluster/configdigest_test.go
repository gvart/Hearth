// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"testing"
	"time"
)

func TestHostFlagsSource(t *testing.T) {
	digest := func(ids ...string) string { return HostFlagsSource(ids)()[ConfigHostFlags] }
	if digest() == "" {
		t.Fatal("no flags have no digest")
	}
	if digest("backup") == digest() {
		t.Error("a dangerous automation granted by flag does not change the digest")
	}
	if digest("x", "y", "x") != digest("y", "x") {
		t.Error("the digest depends on the order or repetition of the flags")
	}
	if got := HostFlagsSource(nil)(); len(got) != 1 {
		t.Errorf("items = %v, want the host flags only", got)
	}
}

// TestConfigDriftHostFlags compares the host flags of three hubs over the
// hubs' mTLS channel: one hub granting a dangerous automation the others do
// not is a difference.
func TestConfigDriftHostFlags(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	for _, h := range hubs {
		h.SetConfigSource(HostFlagsSource([]string{"backup"}))
	}
	wantItem(t, itemOf(t, driftOf(t, hubs[0].testNode), ConfigHostFlags), DriftInSync, allThree, []string{})
	hubs[2].SetConfigSource(HostFlagsSource([]string{"backup", "reboot-nas"}))
	for _, h := range hubs {
		wantItem(t, itemOf(t, driftOf(t, h.testNode), ConfigHostFlags), DriftDiffers,
			[][]string{{"n1", "n2"}, {"n3"}}, []string{})
	}
}
