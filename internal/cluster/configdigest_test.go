// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import "testing"

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
