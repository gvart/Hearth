// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package discovery

import "net/netip"

// defaultGateways finds none on a platform whose routing table the scanner
// cannot read: no host is flagged as the gateway.
func defaultGateways() ([]netip.Addr, error) { return nil, nil }
