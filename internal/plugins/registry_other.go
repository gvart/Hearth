// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package plugins

// CheckInstaller checks nothing where files do not carry an owner the hub
// relies on.
func CheckInstaller(string) error { return nil }
