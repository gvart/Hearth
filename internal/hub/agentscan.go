// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// minScanMinor is the first agent protocol minor version that answers
// ScanRequest and reports the subnets its ceiling lets it scan.
const minScanMinor = 7

// checkScan refuses a scan of subnets unless the agent reported a ceiling
// that allows each of them.
func (s *agentSession) checkScan(device string, subnets []netip.Prefix) error {
	if s.minor < minScanMinor {
		return fmt.Errorf("device %s: agent is too old to scan the network; upgrade it: %w", device, policy.ErrBeyondCeiling)
	}
	s.mu.Lock()
	c := s.ceiling
	s.mu.Unlock()
	if err := policy.ScanWithinCeiling(c, subnets); err != nil {
		return fmt.Errorf("device %s: %w (start its agent with --allow-scan for the subnet)", device, err)
	}
	return nil
}

// deliverScan hands a scan result to the request waiting for it, as deliver
// does.
func (s *agentSession) deliverScan(r *agentv1.ScanResult) {
	s.mu.Lock()
	ch := s.scans[r.GetId()]
	delete(s.scans, r.GetId())
	s.mu.Unlock()
	if ch != nil {
		ch <- r
	}
}

// CheckScan reports whether a scan of subnets would be sent to the agent of
// device: it fails with an error wrapping policy.ErrBeyondCeiling when the
// agent is too old to scan or its reported ceiling does not allow every
// subnet, and with ErrAgentNotConnected when the agent has no open stream to
// this hub.
func (a *Agents) CheckScan(ctx context.Context, device string, subnets []netip.Prefix) error {
	s, err := a.session(ctx, device)
	if master, id, ok := a.forwardTo(ctx, device, err); ok {
		_, err := a.call(ctx, master, "scan", agentCall{Device: id, Subnets: prefixStrings(subnets), CheckOnly: true}, nil, nil)
		return err
	}
	if err != nil {
		return err
	}
	return s.checkScan(device, subnets)
}

// Scan has the agent of device (an id, name or hostname) sweep subnets for
// network discovery within timeout, and waits for its result, as Exec does.
// It returns the device's id with the result. A scan the agent's reported
// ceiling does not allow is never sent: Scan fails with an error wrapping
// policy.ErrBeyondCeiling.
func (a *Agents) Scan(ctx context.Context, device string, subnets []netip.Prefix, timeout time.Duration) (string, *agentv1.ScanResult, error) {
	id, err := a.resolve(ctx, device)
	if err != nil {
		return "", nil, err
	}
	a.mu.Lock()
	s := a.sessions[id]
	a.mu.Unlock()
	if s == nil {
		err := fmt.Errorf("device %s: %w", device, ErrAgentNotConnected)
		if master, id, ok := a.forwardTo(ctx, device, err); ok {
			res := &agentv1.ScanResult{}
			call := agentCall{Device: id, Subnets: prefixStrings(subnets), TimeoutMS: timeout.Milliseconds()}
			if _, err := a.call(ctx, master, "scan", call, nil, res); err != nil {
				return "", nil, err
			}
			return id, res, nil
		}
		return "", nil, err
	}
	if err := s.checkScan(device, subnets); err != nil {
		return "", nil, err
	}
	req := &agentv1.ScanRequest{Id: strings.ToLower(rand.Text()), Timeout: durationpb.New(timeout)}
	for _, p := range subnets {
		req.Subnets = append(req.Subnets, p.String())
	}
	r, err := roundTrip(ctx, s, device, s.scans, req.Id,
		&agentv1.HubMessage{Payload: &agentv1.HubMessage_ScanRequest{ScanRequest: req}})
	if err != nil {
		return "", nil, err
	}
	return id, r, nil
}
