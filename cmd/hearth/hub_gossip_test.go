// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/cluster"
)

func TestAllowedRoles(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    cluster.RoleSet
		wantErr bool
	}{
		{in: "", want: cluster.HubRoles},
		{in: "master,storage", want: cluster.HubRoles},
		{in: "node,storage,master", want: cluster.RolesOf(cluster.RoleNode, cluster.RoleStorage, cluster.RoleMaster)},
		{in: "storage", want: cluster.RolesOf(cluster.RoleStorage)},
		{in: "master,voter", wantErr: true},
	} {
		got, err := (clusterOptions{allowRoles: tc.in}).allowedRoles()
		if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
			t.Errorf("allowedRoles(%q) = %v, %v; want %v (err %v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

// TestHubRefusesRolesOutsideAllowRoles: a hub is master and storage, so a
// host that does not allow both does not start one.
func TestHubRefusesRolesOutsideAllowRoles(t *testing.T) {
	for _, tc := range []struct{ allow, wantErr string }{
		{"storage", "role master not allowed"},
		{"node", "role storage,master not allowed"},
		{"master,leader", `unknown role "leader"`},
	} {
		opts := hubOptions{
			dataDir: t.TempDir(), listen: "127.0.0.1:0", httpListen: "127.0.0.1:0",
			cluster: clusterOptions{allowRoles: tc.allow},
		}
		err := runHub(t.Context(), opts, slog.New(slog.DiscardHandler))
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("--allow-roles %s: runHub = %v, want %q", tc.allow, err, tc.wantErr)
		}
	}
}

func TestGossipAdvertiseAddr(t *testing.T) {
	host := hostnameOr("localhost")
	for _, tc := range []struct {
		opts clusterOptions
		want string
	}{
		{clusterOptions{raftListen: ":7444", gossipListen: ":7445"}, host + ":7445"},
		{clusterOptions{raftListen: ":7444", advertise: "hub-b.lan:7444", gossipListen: ":7445"}, "hub-b.lan:7445"},
		{clusterOptions{raftListen: "10.0.0.5:7444", gossipListen: "0.0.0.0:9000"}, "10.0.0.5:9000"},
		{clusterOptions{gossipListen: ":7445", gossipAdvertise: "10.0.0.9:7999"}, "10.0.0.9:7999"},
	} {
		got, err := tc.opts.gossipAdvertiseAddr()
		if err != nil || got != tc.want {
			t.Errorf("%+v: gossipAdvertiseAddr = %q, %v; want %q", tc.opts, got, err, tc.want)
		}
	}
	if _, err := (clusterOptions{gossipAdvertise: "no-port"}).gossipAdvertiseAddr(); err == nil {
		t.Error("accepted a gossip advertise address without a port")
	}
}

// TestClusterStatusListsMembers: a clustered hub gossips, and `hearth
// cluster status` lists it as a member with its roles.
func TestClusterStatusListsMembers(t *testing.T) {
	dataDir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runHub(ctx, hubOptions{
			dataDir: dataDir, listen: "127.0.0.1:0", httpListen: "127.0.0.1:0", hosts: []string{"127.0.0.1"},
			cluster: clusterOptions{form: true, nodeID: "h1", raftListen: "127.0.0.1:0", gossipListen: "127.0.0.1:0"},
		}, slog.New(slog.DiscardHandler))
	}()

	var st cluster.Status
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if cc, err := cluster.DialControl(dataDir); err == nil {
			st, err = cc.Status(t.Context())
			cc.Close()
			if err == nil && len(st.Members) == 1 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no gossip member in the status: %+v", st)
		}
	}
	if m := st.Members[0]; m.ID != "h1" || m.State != cluster.MemberAlive || m.Roles != cluster.HubRoles ||
		m.AllowedRoles != cluster.HubRoles || m.Schema == 0 || !strings.HasPrefix(m.Address, "127.0.0.1:") {
		t.Errorf("member = %+v", m)
	}

	var out bytes.Buffer
	if err := runClusterStatus(t.Context(), dataDir, false, &out); err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile(`(?m)^h1\s+127\.0\.0\.1:\d+\s+storage,master\s+storage,master\s+alive\s+\d+`)
	if !strings.Contains(out.String(), "MEMBER") || !row.MatchString(out.String()) {
		t.Errorf("status output:\n%s", out.String())
	}
	out.Reset()
	if err := runClusterStatus(t.Context(), dataDir, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"members"`) || !strings.Contains(out.String(), `"allowed_roles": [`) {
		t.Errorf("status JSON:\n%s", out.String())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runHub = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("hub did not stop on cancel")
	}
}
