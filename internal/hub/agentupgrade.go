// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// minUpgradeMinor is the first agent protocol minor version that answers
// UpgradeRequest: it upgrades itself (#347).
const minUpgradeMinor = 11

// errAgentTooOld refuses an upgrade to an agent older than minUpgradeMinor,
// and errNoSelfUpgrade one to an agent that said it does not upgrade
// itself. Both are beyond what the device allows, so policy audits them as
// denials.
var (
	errAgentTooOld = fmt.Errorf("the agent is too old to upgrade itself: upgrade it once with the installer on the device; "+
		"remote upgrades work after that: %w", policy.ErrBeyondCeiling)
	errNoSelfUpgrade = fmt.Errorf("the agent does not upgrade itself: %w", policy.ErrBeyondCeiling)
)

// setNoUpgrade records why the agent said, in its facts, that it does not
// upgrade itself.
func (s *agentSession) setNoUpgrade(why string) {
	s.mu.Lock()
	s.noUpgrade = why
	s.mu.Unlock()
}

// checkUpgrade refuses an upgrade unless the agent upgrades itself.
func (s *agentSession) checkUpgrade(device string) error {
	if s.minor < minUpgradeMinor {
		return fmt.Errorf("device %s: %w", device, errAgentTooOld)
	}
	s.mu.Lock()
	why := s.noUpgrade
	s.mu.Unlock()
	if why != "" {
		return fmt.Errorf("device %s: %s: %w", device, why, errNoSelfUpgrade)
	}
	return nil
}

// deliverUpgrade hands an upgrade result to the request waiting for it, as
// deliver does.
func (s *agentSession) deliverUpgrade(r *agentv1.UpgradeResult) {
	s.mu.Lock()
	ch := s.upgrades[r.GetId()]
	delete(s.upgrades, r.GetId())
	s.mu.Unlock()
	if ch != nil {
		ch <- r
	}
}

// CheckUpgrade reports whether an UpgradeRequest would be sent to the agent
// of device: it fails with an error wrapping policy.ErrBeyondCeiling when
// the agent is too old to upgrade itself or said it does not, and with
// ErrAgentNotConnected when the agent has no open stream to this hub.
func (a *Agents) CheckUpgrade(ctx context.Context, device string) error {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		_, err := a.call(ctx, master, "upgrade", agentCall{Device: id, CheckOnly: true}, nil, nil)
		return err
	}
	if err != nil {
		return err
	}
	return s.checkUpgrade(device)
}

// Upgrade sends req to the agent of device and waits, until ctx ends, for
// its result: the agent downloads, checks and puts the new binary in place,
// answers, then restarts. A request to an agent that does not upgrade itself
// is never sent.
func (a *Agents) Upgrade(ctx context.Context, device string, req *agentv1.UpgradeRequest) (*agentv1.UpgradeResult, error) {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		res := &agentv1.UpgradeResult{}
		if _, err := a.call(ctx, master, "upgrade", agentCall{Device: id}, req, res); err != nil {
			return nil, err
		}
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.checkUpgrade(device); err != nil {
		return nil, err
	}
	req.Id = strings.ToLower(rand.Text())
	return roundTrip(ctx, s, device, s.upgrades, req.Id,
		&agentv1.HubMessage{Payload: &agentv1.HubMessage_UpgradeRequest{UpgradeRequest: req}})
}

// errUpgradeFailed is an upgrade the agent tried and could not finish: its
// old binary stays in place.
var errUpgradeFailed = errors.New("the agent could not upgrade")
