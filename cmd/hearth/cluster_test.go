// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/cluster"
)

func TestClusterCommandsNeedAHub(t *testing.T) {
	dir := t.TempDir()
	const want = "holds no hub"
	for name, err := range map[string]error{
		"status":       runClusterStatus(t.Context(), dir, false, io.Discard),
		"token create": runClusterTokenCreate(t.Context(), clusterTokenOptions{dataDir: dir, ttl: time.Minute, roles: "storage,master"}, io.Discard),
		"remove":       runClusterRemove(t.Context(), dir, "hub-b", false, io.Discard),
		"ca rotate":    runClusterCARotate(t.Context(), dir, false, false, io.Discard),
		"ca finish":    runClusterCAFinish(t.Context(), dir, false, false, io.Discard),
		"ca status":    runClusterCAStatus(t.Context(), dir, io.Discard),
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	if err := runClusterRemove(t.Context(), dir, "Bad ID", false, io.Discard); err == nil || !strings.Contains(err.Error(), "invalid node ID") {
		t.Errorf("remove with an invalid ID: err = %v", err)
	}
}

func TestAdvertiseAddr(t *testing.T) {
	host := dialableHost(t.Context(), hostnameOr("localhost"))
	lan := []netip.Addr{netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("10.0.0.7")}
	tests := []struct {
		opts  clusterOptions
		hosts []string
		lan   []netip.Addr
		want  string
	}{
		// No LAN address: the hostname if it resolves beyond loopback.
		{clusterOptions{listen: ":7444"}, nil, nil, host + ":7444"},
		{clusterOptions{listen: "0.0.0.0:9000"}, nil, nil, host + ":9000"},
		// A bare hub advertises its first LAN address, not its hostname.
		{clusterOptions{listen: ":7444"}, nil, lan, "192.168.1.20:7444"},
		// The first --host that is not loopback comes first.
		{clusterOptions{listen: ":7444"}, []string{"localhost", "hub.lan"}, lan, "hub.lan:7444"},
		{clusterOptions{listen: ":7444"}, []string{"127.0.0.1"}, lan, "192.168.1.20:7444"},
		{clusterOptions{listen: "10.0.0.5:7444"}, []string{"hub.lan"}, lan, "10.0.0.5:7444"},
		{clusterOptions{listen: ":7444", advertise: "hub-b.lan:7999"}, []string{"hub.lan"}, lan, "hub-b.lan:7999"},
	}
	for _, tt := range tests {
		got, err := tt.opts.advertiseAddr(t.Context(), tt.hosts, tt.lan)
		if err != nil || got != tt.want {
			t.Errorf("%+v %v %v: advertiseAddr = %q, %v; want %q", tt.opts, tt.hosts, tt.lan, got, err, tt.want)
		}
	}
	if _, err := (clusterOptions{advertise: "no-port"}).advertiseAddr(t.Context(), nil, nil); err == nil {
		t.Error("accepted an advertise address without a port")
	}
}

// A host name that resolves only to loopback (Debian's 127.0.1.1) is not
// advertised: other members could not dial it.
func TestDialableHostSkipsLoopback(t *testing.T) {
	got := dialableHost(t.Context(), "localhost")
	if ip := net.ParseIP(got); ip == nil || (ip.IsLoopback() && got != "127.0.0.1") {
		t.Fatalf("dialableHost(localhost) = %q, want a private address or 127.0.0.1", got)
	}
}

func TestJoinNeedsAToken(t *testing.T) {
	opts := hubOptions{dataDir: t.TempDir(), cluster: clusterOptions{join: "https://127.0.0.1:1", listen: "127.0.0.1:0"}}
	_, _, _, err := startClusterNode(t.Context(), opts, cluster.HubRoles, "", slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "HEARTH_JOIN_TOKEN") {
		t.Fatalf("err = %v, want a pointer to HEARTH_JOIN_TOKEN", err)
	}
}

func TestRemovedIn(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Minute:                  "soon",
		30 * time.Second:              "in <1m",
		10 * time.Minute:              "in ~10m",
		23*time.Hour + 40*time.Minute: "in ~24h",
		90 * time.Minute:              "in ~2h",
	} {
		if got := removedIn(d); got != want {
			t.Errorf("removedIn(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestStatusShowsAutoRemoval(t *testing.T) {
	at := time.Now().Add(5 * time.Hour)
	var out strings.Builder
	if err := writeStatus(&out, cluster.Status{NodeID: "a", Members: []cluster.MemberInfo{
		{ID: "a", State: cluster.MemberAlive},
		{ID: "c", State: cluster.MemberDead, AutoRemoveAt: &at},
	}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "dead, removed automatically in ~5h") {
		t.Fatalf("status:\n%s", out.String())
	}
}
