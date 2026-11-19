// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadCARefusesAnotherCAsKey: a ca.key copied in by hand, as after a
// restore without it, must belong to ca.crt.
func TestLoadCARefusesAnotherCAsKey(t *testing.T) {
	mine, other := t.TempDir(), t.TempDir()
	for _, dir := range []string{mine, other} {
		if _, err := LoadOrCreateCA(dir, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadOrCreateCA(mine, time.Now()); err != nil {
		t.Fatalf("the CA's own key: %v", err)
	}
	if err := os.Rename(filepath.Join(other, CAKeyFile), filepath.Join(mine, CAKeyFile)); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreateCA(mine, time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not match the CA certificate") {
		t.Fatalf("another CA's key: %v, want refused", err)
	}
}
