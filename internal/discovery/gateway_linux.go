// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"fmt"
	"net/netip"
	"os"
)

// defaultGateways reads the gateways of the kernel's IPv4 default routes,
// which any user may read.
func defaultGateways() ([]netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("read default gateway: %w", err)
	}
	defer f.Close()
	gws, err := parseProcRoute(f)
	if err != nil {
		return nil, fmt.Errorf("read default gateway: %w", err)
	}
	return gws, nil
}
