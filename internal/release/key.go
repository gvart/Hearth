// SPDX-License-Identifier: AGPL-3.0-only

//go:build !e2etestkey

package release

// trustedKey is the key releases are checked against: the release key.
func trustedKey() string { return PublicKey }
