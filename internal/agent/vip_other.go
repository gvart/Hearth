// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// VIPSupported reports whether this platform's agent can claim and release
// virtual IPs (Ceiling.VIP).
const VIPSupported = false

// announce refuses: only Linux agents claim virtual IPs.
func announce(context.Context, *net.Interface, netip.Addr) error {
	return errors.New("virtual IPs are supported on Linux only")
}
