// SPDX-License-Identifier: AGPL-3.0-only

//go:build !tailscale

package main

import "log/slog"

// tailscaleBuilt is whether this build has Tailscale: this one, without the
// tailscale build tag, does not.
const tailscaleBuilt = false

func newTailnetNode(tailnetConfig, *slog.Logger) (tailnetNode, error) { return nil, errNoTailscale }
