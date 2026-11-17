// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestClusterCommandsNeedAMember(t *testing.T) {
	dir := t.TempDir()
	if err := runClusterStatus(t.Context(), dir, false, io.Discard); err == nil || !strings.Contains(err.Error(), "not a cluster member") {
		t.Errorf("status: err = %v", err)
	}
	err := runClusterTokenCreate(t.Context(), clusterTokenOptions{dataDir: dir, ttl: time.Minute}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--cluster") {
		t.Errorf("token create: err = %v", err)
	}
	if err := runClusterRemove(t.Context(), dir, "hub-b", io.Discard); err == nil || !strings.Contains(err.Error(), "not a cluster member") {
		t.Errorf("remove: err = %v", err)
	}
	if err := runClusterTransfer(t.Context(), dir, "", io.Discard); err == nil || !strings.Contains(err.Error(), "not a cluster member") {
		t.Errorf("transfer-leadership: err = %v", err)
	}
	if err := runClusterRemove(t.Context(), dir, "Bad ID", io.Discard); err == nil || !strings.Contains(err.Error(), "invalid node ID") {
		t.Errorf("remove with an invalid ID: err = %v", err)
	}
}

func TestStandaloneHubIsNotClustered(t *testing.T) {
	if (clusterOptions{raftListen: ":7444"}).clustered(t.TempDir()) {
		t.Fatal("a hub without cluster flags or Raft state runs as a cluster member")
	}
}

func TestAdvertiseAddr(t *testing.T) {
	host := hostnameOr("localhost")
	tests := []struct {
		opts clusterOptions
		want string
	}{
		{clusterOptions{raftListen: ":7444"}, host + ":7444"},
		{clusterOptions{raftListen: "0.0.0.0:9000"}, host + ":9000"},
		{clusterOptions{raftListen: "10.0.0.5:7444"}, "10.0.0.5:7444"},
		{clusterOptions{raftListen: ":7444", advertise: "hub-b.lan:7444"}, "hub-b.lan:7444"},
	}
	for _, tt := range tests {
		got, err := tt.opts.advertiseAddr()
		if err != nil || got != tt.want {
			t.Errorf("%+v: advertiseAddr = %q, %v; want %q", tt.opts, got, err, tt.want)
		}
	}
	if _, err := (clusterOptions{advertise: "no-port"}).advertiseAddr(); err == nil {
		t.Error("accepted an advertise address without a port")
	}
}

func TestJoinNeedsAToken(t *testing.T) {
	opts := hubOptions{dataDir: t.TempDir(), cluster: clusterOptions{join: "https://127.0.0.1:1", raftListen: "127.0.0.1:0"}}
	_, _, _, err := startClusterNode(t.Context(), opts, slog.New(slog.DiscardHandler), func(error) {}, "", "")
	if err == nil || !strings.Contains(err.Error(), "HEARTH_JOIN_TOKEN") {
		t.Fatalf("err = %v, want a pointer to HEARTH_JOIN_TOKEN", err)
	}
	opts.cluster.form = true
	if _, _, _, err := startClusterNode(t.Context(), opts, slog.New(slog.DiscardHandler), func(error) {}, "", ""); err == nil {
		t.Fatal("accepted --cluster with --join")
	}
}
