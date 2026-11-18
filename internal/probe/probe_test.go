// SPDX-License-Identifier: AGPL-3.0-only

package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	for _, tc := range []struct {
		path    string
		want    int
		wantErr string
	}{
		{"/", 0, ""},
		{"/down", 0, "status 503"},
		{"/", 204, "status 200"},
		{"/down", 503, ""},
	} {
		err := Run(t.Context(), &agentv1.ProbeRequest{Probe: &agentv1.ProbeRequest_Http{
			Http: &agentv1.HTTPProbe{Url: srv.URL + tc.path, Status: int32(tc.want)}, //nolint:gosec // test values
		}})
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
			t.Errorf("GET %s want %d = %v, want %q", tc.path, tc.want, err, tc.wantErr)
		}
	}
}

func TestHTTPErrorHidesURL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	err = HTTP(t.Context(), "http://admin:s3cret@"+addr+"/?token=t0ken", 0)
	if err == nil || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "t0ken") {
		t.Errorf("HTTP = %v, want a failure that does not repeat the URL", err)
	}
}

func TestTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := TCP(t.Context(), addr); err != nil {
		t.Errorf("TCP to an open port = %v", err)
	}
	_ = ln.Close()
	if err := TCP(t.Context(), addr); err == nil {
		t.Error("TCP to a closed port = nil")
	}
}

func TestDNSNoServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String() // bound but silent: the query times out
	defer pc.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	err = Run(ctx, &agentv1.ProbeRequest{Probe: &agentv1.ProbeRequest_Dns{Dns: &agentv1.DNSProbe{Name: "pi.hole", Server: addr}}})
	if err == nil {
		t.Fatal("DNS without an answer = nil")
	}
}

func TestRunInvalid(t *testing.T) {
	if err := Run(t.Context(), &agentv1.ProbeRequest{}); err == nil {
		t.Error("Run of no probe = nil")
	}
	if err := Run(t.Context(), &agentv1.ProbeRequest{Probe: &agentv1.ProbeRequest_Dns{Dns: &agentv1.DNSProbe{Server: "127.0.0.1:53"}}}); err == nil {
		t.Error("Run of a DNS probe without a name = nil")
	}
}
