// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"testing"
	"time"
)

// TestDeviceCeilingVersion: each write of a device's ceiling gets a higher
// version, which the hub sends with it so the agent can refuse an older one.
func TestDeviceCeilingVersion(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	now := time.Now()
	if err := s.DeviceCeilings().Set(ctx, "pi", []byte(`{"shell":true}`), "web/a", now); err != nil {
		t.Fatal(err)
	}
	first, err := s.DeviceCeilings().Get(ctx, "pi")
	if err != nil || first.Version == 0 {
		t.Fatalf("first = %+v, %v; want a version", first, err)
	}
	// The same wall clock: the version still moves on.
	if err := s.DeviceCeilings().Set(ctx, "pi", []byte(`{}`), "web/a", now); err != nil {
		t.Fatal(err)
	}
	second, err := s.DeviceCeilings().Get(ctx, "pi")
	if err != nil || second.Version <= first.Version {
		t.Fatalf("second version %d after %d, %v; want higher", second.Version, first.Version, err)
	}
}
