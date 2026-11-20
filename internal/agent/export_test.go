// SPDX-License-Identifier: AGPL-3.0-only

package agent

import agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"

// WithNetEdgesReader makes Run read network edges with read instead of the
// platform's reader, so tests on any OS see what is sent.
func WithNetEdgesReader(cfg Config, read func() (*agentv1.NetEdges, error)) Config {
	cfg.readNetEdges = read
	return cfg
}
