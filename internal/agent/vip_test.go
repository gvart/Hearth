// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func vipReq(iface, address string, release bool) *agentv1.ExecRequest {
	return &agentv1.ExecRequest{Id: "1", Action: &agentv1.ExecRequest_Vip{
		Vip: &agentv1.VirtualIP{Interface: iface, Address: address, Release: release},
	}}
}

func TestVIPArgv(t *testing.T) {
	tests := []struct {
		iface, address string
		release        bool
		want           string // "" for an error
	}{
		{"eth0", "192.168.1.53/24", false, "ip -4 address add 192.168.1.53/24 dev eth0"},
		{"eth0", "192.168.1.53/24", true, "ip -4 address del 192.168.1.53/24 dev eth0"},
		{"wlan0", "10.0.0.5/32", false, "ip -4 address add 10.0.0.5/32 dev wlan0"},
		{"eth0", "192.168.1.53", false, ""},
		{"eth0", "not-an-ip/24", false, ""},
		{"eth0", "fd00::53/64", false, ""},
		{"eth0 dev lo", "192.168.1.53/24", false, ""},
		{"-force", "192.168.1.53/24", false, ""},
		{"lo", "127.0.0.2/8", false, ""},
		{"", "192.168.1.53/24", true, ""},
	}
	for _, tt := range tests {
		argv, err := vipArgv(&agentv1.VirtualIP{Interface: tt.iface, Address: tt.address, Release: tt.release})
		if got := strings.Join(argv, " "); got != tt.want || (err == nil) != (tt.want != "") {
			t.Errorf("vipArgv(%q, %q, %v) = %q, %v; want %q", tt.iface, tt.address, tt.release, got, err, tt.want)
		}
	}
}

func TestParseVIP(t *testing.T) {
	if err := ParseVIP("eth0=192.168.1.53/24"); err != nil {
		t.Errorf("ParseVIP: %v", err)
	}
	for _, bad := range []string{"eth0", "192.168.1.53/24", "eth0=192.168.1.53", "lo=10.0.0.1/8", "eth0=10.0.0.0/8"} {
		if ParseVIP(bad) == nil {
			t.Errorf("ParseVIP(%q) = nil, want an error", bad)
		}
	}
}

func TestGARPFrame(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x53}
	ip := netip.MustParseAddr("192.168.1.53")
	bcast := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, op := range []uint16{arpRequest, arpReply} {
		f := garpFrame(mac, ip, op)
		if len(f) != 42 {
			t.Fatalf("frame is %d bytes", len(f))
		}
		checks := []struct {
			what      string
			got, want []byte
		}{
			{"destination", f[0:6], bcast},
			{"source", f[6:12], mac},
			{"ethertype", f[12:14], []byte{0x08, 0x06}},
			{"hardware, protocol, sizes", f[14:20], []byte{0, 1, 0x08, 0, 6, 4}},
			{"operation", f[20:22], binary.BigEndian.AppendUint16(nil, op)},
			{"sender MAC", f[22:28], mac},
			{"sender IP", f[28:32], []byte{192, 168, 1, 53}},
			{"target IP", f[38:42], []byte{192, 168, 1, 53}},
		}
		for _, c := range checks {
			if !bytes.Equal(c.got, c.want) {
				t.Errorf("op %d %s = % x, want % x", op, c.what, c.got, c.want)
			}
		}
	}
}

// fakeVIPOps records what moveVIP does.
type fakeVIPOps struct {
	mac   net.HardwareAddr
	addrs []net.Addr
	runs  [][]string
	garps []netip.Addr
}

func (f *fakeVIPOps) ops() vipOps {
	return vipOps{
		iface: func(name string) (*net.Interface, []net.Addr, error) {
			if name != "eth0" {
				return nil, nil, errors.New("no such interface")
			}
			return &net.Interface{Name: name, Index: 2, HardwareAddr: f.mac}, f.addrs, nil
		},
		run: func(_ context.Context, argv []string) error {
			f.runs = append(f.runs, argv)
			return nil
		},
		garp: func(_ context.Context, _ *net.Interface, ip netip.Addr) error {
			f.garps = append(f.garps, ip)
			return nil
		},
	}
}

func TestMoveVIP(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	own := &net.IPNet{IP: net.IPv4(192, 168, 1, 11), Mask: net.CIDRMask(24, 32)}
	vip := &net.IPNet{IP: net.IPv4(192, 168, 1, 53), Mask: net.CIDRMask(24, 32)}
	tests := []struct {
		name     string
		mac      net.HardwareAddr
		iface    string
		addrs    []net.Addr
		release  bool
		wantRun  string
		wantGARP bool
		wantErr  string
	}{
		{name: "claim", mac: mac, addrs: []net.Addr{own}, wantRun: "add", wantGARP: true},
		{name: "claim held: announce again", mac: mac, addrs: []net.Addr{own, vip}, wantGARP: true},
		{name: "release held", mac: mac, addrs: []net.Addr{own, vip}, release: true, wantRun: "del"},
		{name: "release not held", mac: mac, addrs: []net.Addr{own}, release: true},
		{name: "release without MAC", addrs: []net.Addr{vip}, release: true, wantRun: "del"},
		{name: "claim without MAC", addrs: []net.Addr{own}, wantErr: "no Ethernet address"},
		{name: "no interface", iface: "eth9", mac: mac, wantErr: "no such interface"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeVIPOps{mac: tt.mac, addrs: tt.addrs}
			iface := tt.iface
			if iface == "" {
				iface = "eth0"
			}
			err := moveVIP(t.Context(), vipReq(iface, "192.168.1.53/24", tt.release).GetVip(), f.ops())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if len(f.runs) != 0 || len(f.garps) != 0 {
					t.Errorf("ran %v, announced %v after a refusal", f.runs, f.garps)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tt.wantRun == "" && len(f.runs) != 0:
				t.Errorf("ran %v, want nothing", f.runs)
			case tt.wantRun != "" && (len(f.runs) != 1 || f.runs[0][3] != tt.wantRun):
				t.Errorf("ran %v, want ip address %s", f.runs, tt.wantRun)
			}
			if want := tt.wantGARP; (len(f.garps) == 1 && f.garps[0] == netip.MustParseAddr("192.168.1.53")) != want {
				t.Errorf("announced %v, want announced %v", f.garps, want)
			}
		})
	}
}

// The agent refuses a virtual IP its ceiling does not list, whatever the hub
// checked, and off Linux refuses every one.
func TestExecuteVIPRefusals(t *testing.T) {
	allowed := Ceiling{VIP: []string{"eth0=192.168.1.53/24"}}
	tests := []struct {
		name   string
		c      Ceiling
		req    *agentv1.ExecRequest
		denied bool
	}{
		{"empty ceiling", Ceiling{}, vipReq("eth0", "192.168.1.53/24", false), true},
		{"exec of ip is not enough", Ceiling{Exec: []string{"ip", "/usr/sbin/ip"}}, vipReq("eth0", "192.168.1.53/24", false), true},
		{"other address", allowed, vipReq("eth0", "192.168.1.1/24", false), true},
		{"other interface", allowed, vipReq("wlan0", "192.168.1.53/24", true), true},
		{"invalid interface", allowed, vipReq("eth0 dev lo", "192.168.1.53/24", false), false},
	}
	for _, tt := range tests {
		res := tt.c.execute(t.Context(), tt.req)
		if res.GetDenied() != tt.denied || res.GetError() == "" || res.GetExitCode() != -1 {
			t.Errorf("%s: result %v, want denied %v with an error", tt.name, res, tt.denied)
		}
	}
	if !VIPSupported {
		res := allowed.execute(t.Context(), vipReq("eth0", "192.168.1.53/24", false))
		if res.GetDenied() || !strings.Contains(res.GetError(), "Linux only") {
			t.Errorf("off Linux: result %v, want refused as Linux only", res)
		}
	}
}

// A ceiling the hub sets keeps its virtual IPs on Linux only, and refuses a
// bad entry whole.
func TestHubCeilingVIP(t *testing.T) {
	c, err := checkHubCeiling(Ceiling{VIP: []string{"eth0=192.168.1.53/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(c.VIP) == 1; got != VIPSupported {
		t.Errorf("vip kept = %v on a platform where VIPSupported = %v", c.VIP, VIPSupported)
	}
	if _, err := checkHubCeiling(Ceiling{VIP: []string{"eth0=192.168.1.53/24", "lo=127.0.0.2/8"}}); err == nil {
		t.Error("a bad vip entry was accepted")
	}
	a, b := Ceiling{VIP: []string{"eth0=192.168.1.53/24"}}, Ceiling{VIP: []string{"eth1=10.0.0.53/24"}}
	if u := a.union(b); !slices.Equal(u.VIP, []string{"eth0=192.168.1.53/24", "eth1=10.0.0.53/24"}) || u.equal(a) {
		t.Errorf("union = %v", u.VIP)
	}
	if got := ceilingOf(a.proto()); !got.equal(a) {
		t.Errorf("round trip = %v, want %v", got.VIP, a.VIP)
	}
}
