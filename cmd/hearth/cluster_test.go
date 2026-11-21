// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"log/slog"
	"net"
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
		"token create": runClusterTokenCreate(t.Context(), clusterTokenOptions{dataDir: dir, ttl: time.Minute}, io.Discard),
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
	tests := []struct {
		opts clusterOptions
		want string
	}{
		{clusterOptions{listen: ":7444"}, host + ":7444"},
		{clusterOptions{listen: "0.0.0.0:9000"}, host + ":9000"},
		{clusterOptions{listen: "10.0.0.5:7444"}, "10.0.0.5:7444"},
		{clusterOptions{listen: ":7444", advertise: "hub-b.lan:7999"}, "hub-b.lan:7999"},
	}
	for _, tt := range tests {
		got, err := tt.opts.advertiseAddr(t.Context())
		if err != nil || got != tt.want {
			t.Errorf("%+v: advertiseAddr = %q, %v; want %q", tt.opts, got, err, tt.want)
		}
	}
	if _, err := (clusterOptions{advertise: "no-port"}).advertiseAddr(t.Context()); err == nil {
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
