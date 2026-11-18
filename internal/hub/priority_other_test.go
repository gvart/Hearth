// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package hub

// niceCheck is Linux only, where nice is per thread.
func niceCheck() int { return 0 }
