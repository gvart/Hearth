// SPDX-License-Identifier: AGPL-3.0-only

package s3

import (
	"strings"
	"testing"
)

func TestValidBucket(t *testing.T) {
	for name, want := range map[string]bool{
		"hearth-backups":        true,
		"hearth.backups.2026":   true,
		"abc":                   true,
		strings.Repeat("a", 63): true,
		"ab":                    false,
		strings.Repeat("a", 64): false,
		"Hearth":                false,
		"hearth_backups":        false,
		"-hearth":               false,
		"hearth-":               false,
		"hearth..backups":       false,
		"192.168.1.10":          false,
		"hearth/backups":        false,
		"":                      false,
	} {
		if got := validBucket(name); got != want {
			t.Errorf("validBucket(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestErrorCodeIsCapped(t *testing.T) {
	long := strings.Repeat("X", 500)
	got := errorCode(strings.NewReader("<Error><Code>" + long + "</Code></Error>"))
	if len(got) != 1+maxErrorCode {
		t.Fatalf("error code of %d characters, want %d", len(got)-1, maxErrorCode)
	}
	if got := errorCode(strings.NewReader("<Error><Code>AccessDenied</Code></Error>")); got != " AccessDenied" {
		t.Fatalf("errorCode = %q", got)
	}
}

// TestCanonicalQuerySortsByKeyThenValue: "a" comes before "a-b", although
// "a-b=" sorts before "a=" as a string.
func TestCanonicalQuerySortsByKeyThenValue(t *testing.T) {
	got := canonicalQuery("a-b=1&a=2&a=1")
	if want := "a=1&a=2&a-b=1"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
