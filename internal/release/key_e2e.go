// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2etestkey

package release

// e2eTestKey is the public key of the end-to-end tests' releases, linked in
// with -ldflags -X by test/e2e/Dockerfile. It exists only in a build with
// the e2etestkey tag, never in a release build; empty, it trusts no key.
var e2eTestKey string

// trustedKey is the key releases are checked against: the test key.
func trustedKey() string { return e2eTestKey }
