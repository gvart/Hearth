// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package agent

// releaseImagePages is a no-op off Linux.
func releaseImagePages() {}
