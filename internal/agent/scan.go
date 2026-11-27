// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

const (
	// defaultScanTimeout applies when a scan request sets none.
	defaultScanTimeout = discovery.AgentScanTimeout
	// maxScanTimeout caps what the hub may ask for.
	maxScanTimeout = 5 * time.Minute
)

// ParseScan checks a Ceiling.Scan entry: an IPv4 CIDR, such as
// 192.168.2.0/24. The hub may have this device sweep that subnet, or a part
// of it.
func ParseScan(entry string) error {
	p, err := netip.ParsePrefix(entry)
	if err != nil {
		return fmt.Errorf("scan entry %q: %w", entry, err)
	}
	if !p.Addr().Is4() {
		return fmt.Errorf("scan entry %q: only IPv4 subnets can be swept", entry)
	}
	return nil
}

// scan runs req, a network discovery scan, if the ceiling allows each of
// its subnets, and reports the hosts that answered. The hub checks the same
// before it sends req; the agent never relies on that, and holds the
// request to the limits of a hub's own scan (IPv4, at most
// discovery.MaxHosts addresses). One scan runs at a time; nothing of it
// stays in memory once it is done.
func (r *runner) scan(ctx context.Context, req *agentv1.ScanRequest) *agentv1.ScanResult {
	res := &agentv1.ScanResult{Id: req.GetId()}
	subnets, auto, err := discovery.ParseSubnets(req.GetSubnets())
	if err == nil && (auto || len(subnets) == 0) {
		err = errors.New("want the IPv4 subnets to scan")
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if err := policy.ScanWithinCeiling(r.ceiling().proto(), subnets); err != nil {
		res.Denied, res.Error = true, err.Error()
		return res
	}
	if !r.scanning.CompareAndSwap(false, true) {
		res.Error = "a scan is already running"
		return res
	}
	defer r.scanning.Store(false)

	timeout := defaultScanTimeout
	if d := req.GetTimeout().AsDuration(); d > 0 {
		timeout = min(d, maxScanTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hosts, err := discovery.Find(ctx, subnets, r.log.With("component", "discovery"))
	if err != nil {
		res.Error = err.Error()
		return res
	}
	for _, h := range hosts {
		res.Hosts = append(res.Hosts, &agentv1.ScannedHost{Mac: h.MAC, Ip: h.IP, Hostname: h.Hostname})
	}
	return res
}
