// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package plugins

import "os"

// checkInfo checks nothing where file modes do not say who may write.
func checkInfo(string, os.FileInfo) error { return nil }

// checkPrivate checks nothing where file modes do not say who may read.
func checkPrivate(string, os.FileInfo) error { return nil }
