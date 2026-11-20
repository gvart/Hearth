// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package agent

import agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"

// NetEdgesSupported reports whether this platform's agent can report its
// network edges (Ceiling.NetEdges).
const NetEdgesSupported = false

// readNetEdges reports nothing: only Linux agents report network edges.
func readNetEdges() (*agentv1.NetEdges, error) { return nil, nil }
