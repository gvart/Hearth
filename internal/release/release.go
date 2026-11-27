// SPDX-License-Identifier: AGPL-3.0-only

// Package release names and orders Hearth's release tags, for the agent
// that upgrades itself and the hub that says when it should (#347).
package release

import (
	"regexp"
	"strconv"
	"strings"
)

// Tag matches a release tag, such as v0.1.0 or v0.1.0-rc.2.
var Tag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

// Compare compares two release tags as semantic versions: -1, 0 or 1.
// v0.0.1-rc.10 is newer than v0.0.1-rc.9, and v0.0.1 than both.
func Compare(a, b string) int {
	ac, ap, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	bc, bp, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	if c := compareIdents(strings.Split(ac, "."), strings.Split(bc, "."), true); c != 0 {
		return c
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	return compareIdents(strings.Split(ap, "."), strings.Split(bp, "."), false)
}

// compareIdents compares dot-separated identifiers as semver does: numbers
// numerically and below words, words in ASCII order, and a shorter list
// first when one is a prefix of the other.
func compareIdents(a, b []string, numeric bool) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aerr := strconv.ParseUint(a[i], 10, 64)
		bn, berr := strconv.ParseUint(b[i], 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case numeric || (aerr != nil && berr != nil):
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		case aerr == nil:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}
