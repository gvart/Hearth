// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// minDockerMinor is the first agent protocol minor version that answers
// DockerRequest and reports whether its ceiling allows docker.
const minDockerMinor = 9

// checkDocker refuses req unless the agent reported a ceiling that allows
// it.
func (s *agentSession) checkDocker(device string, req *agentv1.DockerRequest) error {
	if s.minor < minDockerMinor {
		return fmt.Errorf("device %s: agent is too old for Docker; upgrade it: %w", device, policy.ErrBeyondCeiling)
	}
	s.mu.Lock()
	c := s.ceiling
	s.mu.Unlock()
	if err := policy.DockerWithinCeiling(c, req); err != nil {
		if !c.GetDocker() {
			return fmt.Errorf("device %s: %w (start its agent with --allow-docker)", device, err)
		}
		return fmt.Errorf("device %s: %w", device, err)
	}
	return nil
}

// deliverDocker hands a Docker result to the request waiting for it, as
// deliver does.
func (s *agentSession) deliverDocker(r *agentv1.DockerResult) {
	s.mu.Lock()
	ch := s.dockers[r.GetId()]
	delete(s.dockers, r.GetId())
	s.mu.Unlock()
	if ch != nil {
		ch <- r
	}
}

// CheckDocker reports whether req would be sent to the agent of device: it
// fails with an error wrapping policy.ErrBeyondCeiling when the agent is too
// old for Docker or its reported ceiling does not allow it, wrapping
// policy.ErrDenied when req is not one an agent takes (a verb or container
// it refuses), and with ErrAgentNotConnected when the agent has no open
// stream to this hub.
func (a *Agents) CheckDocker(ctx context.Context, device string, req *agentv1.DockerRequest) error {
	s, err := a.session(ctx, device)
	if err != nil {
		return err
	}
	return s.checkDocker(device, req)
}

// Docker sends req to the agent of device (a device id, name or hostname),
// asking it to finish within timeout, and waits for its result, as Exec
// does. A request the agent's reported ceiling does not allow is never sent.
func (a *Agents) Docker(ctx context.Context, device string, req *agentv1.DockerRequest, timeout time.Duration) (*agentv1.DockerResult, error) {
	s, err := a.session(ctx, device)
	if err != nil {
		return nil, err
	}
	if err := s.checkDocker(device, req); err != nil {
		return nil, err
	}
	req.Id = strings.ToLower(rand.Text())
	req.Timeout = durationpb.New(timeout)
	return roundTrip(ctx, s, device, s.dockers, req.Id,
		&agentv1.HubMessage{Payload: &agentv1.HubMessage_DockerRequest{DockerRequest: req}})
}
