// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/probe"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

const (
	// defaultProbeTimeout applies when a probe request sets none.
	defaultProbeTimeout = 5 * time.Second
	// maxProbeTimeout caps what the hub may ask for.
	maxProbeTimeout = time.Minute
)

// probe runs req if the ceiling allows probes and reports the outcome. The
// hub checks the same before it sends req; the agent never relies on that.
func (c Ceiling) probe(ctx context.Context, req *agentv1.ProbeRequest) *agentv1.ProbeResult {
	res := &agentv1.ProbeResult{Id: req.GetId()}
	if err := policy.ProbeWithinCeiling(c.proto()); err != nil {
		res.Denied, res.Error = true, err.Error()
		return res
	}
	timeout := defaultProbeTimeout
	if d := req.GetTimeout().AsDuration(); d > 0 {
		timeout = min(d, maxProbeTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := probe.Run(ctx, req); err != nil {
		res.Error = err.Error()
	}
	return res
}
