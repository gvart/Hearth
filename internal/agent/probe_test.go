// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func tcpProbe(addr string) *agentv1.ProbeRequest {
	return &agentv1.ProbeRequest{Id: "p1", Probe: &agentv1.ProbeRequest_Tcp{Tcp: &agentv1.TCPProbe{Address: addr}}}
}

// TestCeilingProbe checks the agent enforces --allow-probe itself, whatever
// the hub sends.
func TestCeilingProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	open := ln.Addr().String()

	for _, c := range []Ceiling{{}, {Exec: []string{"/usr/bin/df"}, Restart: []string{"docker:x"}}} {
		res := c.probe(t.Context(), tcpProbe(open))
		if !res.GetDenied() || res.GetId() != "p1" {
			t.Errorf("probe with ceiling %+v = %v, want denied", c, res)
		}
	}
	allowed := Ceiling{Probe: true}
	if res := allowed.probe(t.Context(), tcpProbe(open)); res.GetDenied() || res.GetError() != "" {
		t.Errorf("probe of an open port = %v, want passed", res)
	}
	_ = ln.Close()
	if res := allowed.probe(t.Context(), tcpProbe(open)); res.GetDenied() || res.GetError() == "" {
		t.Errorf("probe of a closed port = %v, want failed", res)
	}
	if !allowed.proto().GetProbe() || (Ceiling{}).proto().GetProbe() {
		t.Error("probe not reported in the ceiling as set")
	}
}
