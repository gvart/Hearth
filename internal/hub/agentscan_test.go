// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

var scanSubnets = []netip.Prefix{netip.MustParsePrefix("10.0.5.0/24")}

func TestAgentsScan(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)

	stream := connectAgent(ctx, t, client, minScanMinor, &agentv1.Ceiling{Scan: []string{"10.0.0.0/16"}})
	got := make(chan *agentv1.ScanRequest, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			req := msg.GetScanRequest()
			got <- req
			_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ScanResult{ScanResult: &agentv1.ScanResult{
				Id: req.GetId(), Hosts: []*agentv1.ScannedHost{{Mac: "2c:cf:67:00:00:01", Ip: "10.0.5.7"}},
			}}})
		}
	}()
	var (
		id  string
		res *agentv1.ScanResult
		err error
	)
	for range 100 {
		if id, res, err = agents.Scan(ctx, "dev-1", scanSubnets, time.Minute); !errors.Is(err, ErrAgentNotConnected) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || id != "dev-1" || len(res.GetHosts()) != 1 {
		t.Fatalf("Scan = %q, %v, %v; want the agent's hosts", id, res, err)
	}
	req := <-got
	if req.GetId() != res.GetId() || len(req.GetSubnets()) != 1 || req.GetSubnets()[0] != "10.0.5.0/24" ||
		req.GetTimeout().AsDuration() != time.Minute {
		t.Errorf("agent got %v, want the subnet and timeout with the result's id", req)
	}
}

func TestAgentsScanNeverBeyondCeiling(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		minor   uint32
		ceiling *agentv1.Ceiling
		want    string
	}{
		"old agent":        {minor: minScanMinor - 1, ceiling: &agentv1.Ceiling{Scan: []string{"10.0.5.0/24"}}, want: "too old"},
		"scan not allowed": {minor: minScanMinor, ceiling: &agentv1.Ceiling{Probe: true, Shell: true}, want: "--allow-scan"},
		"other subnet":     {minor: minScanMinor, ceiling: &agentv1.Ceiling{Scan: []string{"10.0.6.0/24"}}, want: "--allow-scan"},
		"no ceiling":       {minor: minScanMinor, want: "--allow-scan"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			st := newTestStore(t)
			enrollDevice(t, st, "dev-1")
			client, agents := newExecClient(t, st)
			stream := connectAgent(ctx, t, client, tc.minor, tc.ceiling)
			sent := make(chan struct{}, 1)
			go func() {
				if msg, err := stream.Receive(); err == nil && msg.GetScanRequest() != nil {
					sent <- struct{}{}
				}
			}()
			var err error
			for range 100 {
				if _, _, err = agents.Scan(ctx, "dev-1", scanSubnets, time.Second); !errors.Is(err, ErrAgentNotConnected) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !errors.Is(err, policy.ErrBeyondCeiling) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Scan = %v, want beyond the ceiling (%s)", err, tc.want)
			}
			if err := agents.CheckScan(ctx, "dev-1", scanSubnets); !errors.Is(err, policy.ErrBeyondCeiling) {
				t.Errorf("CheckScan = %v, want beyond the ceiling", err)
			}
			select {
			case <-sent:
				t.Error("a scan beyond the ceiling reached the agent")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}
