// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Virtual IPs (#49): the hub moves a service's address, such as the Pi-hole
// every host resolves through, from one device to another. A claim adds the
// address to an interface with ip(8) and announces it with gratuitous ARP,
// so that the hosts of the LAN send to this device from then on; a release
// removes it. The agent takes only the interface=address pairs its ceiling's
// VIP lists (--allow-vip, or the hub's ceiling), on Linux only. The address
// is not saved: it is gone after a reboot.

// ParseVIP checks a Ceiling.VIP entry, IFACE=ADDRESS/PREFIX, as the
// --allow-vip flag takes it.
func ParseVIP(entry string) error {
	return policy.CheckHubCeiling(&agentv1.Ceiling{Vip: []string{entry}})
}

// vipArgv is the ip(8) command that adds (or, for a release, removes) the
// address of v on its interface. Interface and address are checked
// (policy.CheckVIP) and passed as arguments, never through a shell.
func vipArgv(v *agentv1.VirtualIP) ([]string, error) {
	if err := policy.CheckVIP(v.GetInterface(), v.GetAddress()); err != nil {
		return nil, err
	}
	verb := "add"
	if v.GetRelease() {
		verb = "del"
	}
	return []string{"ip", "-4", "address", verb, v.GetAddress(), "dev", v.GetInterface()}, nil
}

// holdsAddr reports whether addrs, an interface's addresses, include addr.
func holdsAddr(addrs []net.Addr, addr netip.Addr) bool {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == addr {
			return true
		}
	}
	return false
}

// ARP operations.
const (
	arpRequest = 1
	arpReply   = 2
)

// garpFrame is an Ethernet frame announcing that mac holds ip: a gratuitous
// ARP of operation op (arpRequest or arpReply), broadcast, whose sender and
// target address are both ip.
func garpFrame(mac net.HardwareAddr, ip netip.Addr, op uint16) []byte {
	f := make([]byte, 42)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // to everyone
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:14], 0x0806) // ARP
	binary.BigEndian.PutUint16(f[14:16], 1)      // Ethernet
	binary.BigEndian.PutUint16(f[16:18], 0x0800) // IPv4
	f[18], f[19] = 6, 4
	binary.BigEndian.PutUint16(f[20:22], op)
	a := ip.As4()
	copy(f[22:28], mac)
	copy(f[28:32], a[:])
	if op == arpReply {
		copy(f[32:38], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	}
	copy(f[38:42], a[:])
	return f
}

// vip claims or releases the virtual IP v of req, if the ceiling allows it,
// and reports the outcome in res.
func (c Ceiling) vip(ctx context.Context, req *agentv1.ExecRequest, v *agentv1.VirtualIP, res *agentv1.ExecResult) *agentv1.ExecResult {
	if err := policy.WithinCeiling(c.proto(), req); err != nil {
		res.Denied = errors.Is(err, policy.ErrBeyondCeiling)
		res.Error = err.Error()
		return res
	}
	if !VIPSupported {
		res.Error = "virtual IPs are supported on Linux only"
		return res
	}
	timeout := defaultExecTimeout
	if d := req.GetTimeout().AsDuration(); d > 0 {
		timeout = min(d, maxExecTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := moveVIP(ctx, v, systemVIPOps); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w after %s: %w", ctx.Err(), timeout, err)
		}
		res.Error = err.Error()
		return res
	}
	res.ExitCode = 0
	return res
}

// vipOps are what moveVIP does to the system; tests replace them.
type vipOps struct {
	// iface returns the interface name and its addresses.
	iface func(name string) (*net.Interface, []net.Addr, error)
	// run runs an ip(8) command.
	run func(ctx context.Context, argv []string) error
	// garp announces that ifi holds ip.
	garp func(ctx context.Context, ifi *net.Interface, ip netip.Addr) error
}

// systemVIPOps act on this device.
var systemVIPOps = vipOps{iface: interfaceAddrs, run: runIP, garp: announce}

// moveVIP claims or releases v: it runs ip(8) unless the interface already
// holds the address (a claim) or does not (a release), and after a claim
// announces the address with gratuitous ARP.
func moveVIP(ctx context.Context, v *agentv1.VirtualIP, ops vipOps) error {
	argv, err := vipArgv(v)
	if err != nil {
		return err
	}
	p, _ := policy.ParseVIPAddress(v.GetAddress())
	ifi, addrs, err := ops.iface(v.GetInterface())
	if err != nil {
		return err
	}
	if !v.GetRelease() && len(ifi.HardwareAddr) != 6 {
		return fmt.Errorf("interface %s has no Ethernet address to announce %s with", ifi.Name, p.Addr())
	}
	if holds := holdsAddr(addrs, p.Addr()); holds == v.GetRelease() {
		if err := ops.run(ctx, argv); err != nil {
			return err
		}
	}
	if v.GetRelease() {
		return nil
	}
	return ops.garp(ctx, ifi, p.Addr())
}

// interfaceAddrs is the interface name and its addresses.
func interfaceAddrs(name string) (*net.Interface, []net.Addr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s: %w", name, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("addresses of %s: %w", name, err)
	}
	return ifi, addrs, nil
}

// runIP runs an ip(8) command, without a shell.
func runIP(ctx context.Context, argv []string) error {
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // vipArgv checked every argument
	if err != nil {
		if tail := lastBytes(out, stderrTail); tail != "" {
			return fmt.Errorf("%s: %w: %s", strings.Join(argv[:4], " "), err, tail)
		}
		return fmt.Errorf("%s: %w", strings.Join(argv[:4], " "), err)
	}
	return nil
}
