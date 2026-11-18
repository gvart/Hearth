// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsServer answers A queries on a local UDP port: with a record while ok,
// with SERVFAIL otherwise. Close stops it, as a stopped Pi-hole.
type dnsServer struct {
	conn net.PacketConn
	ok   atomic.Bool
	done chan struct{}
}

func newDNSServer(t *testing.T) *dnsServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &dnsServer{conn: conn, done: make(chan struct{})}
	s.ok.Store(true)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

func (s *dnsServer) addr() string { return s.conn.LocalAddr().String() }

func (s *dnsServer) Close() {
	if s.conn.Close() == nil {
		<-s.done
	}
}

func (s *dnsServer) serve() {
	defer close(s.done)
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
			continue
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, RCode: dnsmessage.RCodeServerFailure},
			Questions: q.Questions,
		}
		if s.ok.Load() {
			resp.RCode = dnsmessage.RCodeSuccess
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 1, 10}},
			}}
		}
		b, err := resp.Pack()
		if err == nil {
			_, _ = s.conn.WriteTo(b, from)
		}
	}
}

// checkSteps drives a check trigger through the fake clock.
type checkSteps struct {
	t     *testing.T
	clock *fakeClock
	w     *watching
	every time.Duration
}

func startCheck(t *testing.T, src string) *checkSteps {
	t.Helper()
	clock := newFakeClock(time.Unix(1_700_000_000, 0))
	w := watch(t, mustBuildTrigger(t, TriggerDeps{Clock: clock}, src))
	return &checkSteps{t: t, clock: clock, w: w, every: clock.waitForWaiter(t)}
}

// next runs the next check and returns the firings so far.
func (c *checkSteps) next() int32 {
	c.t.Helper()
	c.clock.Advance(c.every)
	c.clock.waitForWaiter(c.t)
	return c.w.fires.Load()
}

func TestDNSCheckDetectsStoppedServer(t *testing.T) {
	srv := newDNSServer(t)
	c := startCheck(t, "type: dns\nname: pi.hole\nserver: "+srv.addr()+"\ntimeout: 1s")
	if c.every != defaultCheckEvery {
		t.Fatalf("checks every %s, want %s", c.every, defaultCheckEvery)
	}
	if n := c.next(); n != 0 {
		t.Fatalf("fired while the server answers")
	}
	srv.ok.Store(false) // SERVFAIL
	if n := c.next(); n != 1 {
		t.Fatalf("fires = %d after SERVFAIL, want 1", n)
	}
	srv.ok.Store(true)
	if n := c.next(); n != 1 {
		t.Fatalf("fires = %d after recovery, want 1", n)
	}
	srv.Close() // stopped: nothing listens on the port
	if n := c.next(); n != 2 {
		t.Fatalf("fires = %d with the server stopped, want 2", n)
	}
	if n := c.next(); n != 2 {
		t.Fatalf("fires = %d while still stopped, want 2: one firing per outage", n)
	}
}

func TestDNSCheckDefaultPort(t *testing.T) {
	tr := mustBuildTrigger(t, TriggerDeps{}, "type: dns\nname: example.com\nserver: 192.168.1.2")
	want := "fires when DNS lookup of example.com A at 192.168.1.2:53 fails (checked every 10s from the hub)"
	if got := tr.Describe(); got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
	tr = mustBuildTrigger(t, TriggerDeps{}, "type: dns\nname: example.com\nserver: '[fd00::1]'\nfor: 30s")
	want = "fires when DNS lookup of example.com A at [fd00::1]:53 fails for 30s (checked every 10s from the hub)"
	if got := tr.Describe(); got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
}

func TestHTTPCheck(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()

	c := startCheck(t, "type: http\nurl: "+srv.URL+"/health\nfor: 20s\ntimeout: 1s")
	status.Store(http.StatusServiceUnavailable)
	if n := c.next(); n != 0 { // failing for 0 s
		t.Fatalf("fired before 20s")
	}
	c.next() // 10 s
	if n := c.next(); n != 1 {
		t.Fatalf("fires = %d after failing 20s, want 1", n)
	}
	status.Store(http.StatusFound) // 3xx is up
	c.next()
	srv.Close() // connection refused
	c.next()
	c.next()
	if n := c.next(); n != 2 {
		t.Fatalf("fires = %d after the server stopped for 20s, want 2", n)
	}
}

func TestHTTPCheckExpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := startCheck(t, "type: http\nurl: "+srv.URL+"\nstatus: 204")
	if n := c.w.fires.Load(); n != 1 {
		t.Fatalf("fires = %d on 200 when 204 is expected, want 1", n)
	}
}

func TestTCPCheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	c := startCheck(t, "type: tcp\naddress: "+addr+"\nevery: 5s\ntimeout: 1s")
	if c.every != 5*time.Second {
		t.Fatalf("checks every %s, want 5s", c.every)
	}
	if n := c.next(); n != 0 {
		t.Fatalf("fired while the port is open")
	}
	_ = ln.Close()
	if n := c.next(); n != 1 {
		t.Fatalf("fires = %d with the port closed, want 1", n)
	}
}

func TestCheckInvalid(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{"type: http\nurl: ftp://nas", "url must be http(s)"},
		{"type: http\nurl: http://nas\nstatus: 42", "not an HTTP status"},
		{"type: http\nurl: http://nas\nevery: 0.5s", "at least 1s"},
		{"type: tcp\naddress: nas", "host:port"},
		{"type: tcp\naddress: ':22'", "host:port"},
		{"type: dns\nserver: 1.1.1.1", "name must be a domain name"},
		{"type: dns\nname: example.com", "server is required"},
		{"type: dns\nname: example.com\nserver: 1.1.1.1\nrecord: MX", `unknown field "record"`},
	} {
		_, err := buildTrigger(t, TriggerDeps{}, tc.src)
		wantErrContains(t, err, tc.want)
	}
}

func TestHTTPCheckRedactsPassword(t *testing.T) {
	tr := mustBuildTrigger(t, TriggerDeps{}, "type: http\nurl: http://admin:s3cret@nas.lan/")
	if got := tr.Describe(); strings.Contains(got, "s3cret") {
		t.Errorf("Describe leaks the password: %q", got)
	}
}

func TestHTTPCheckRedactsQueryValues(t *testing.T) {
	clock := newFakeClock(time.Now())
	tr := mustBuildTrigger(t, TriggerDeps{Clock: clock},
		"type: http\nurl: http://admin:s3cret@127.0.0.1:1/ping?token=t0ken&x=1#frag")
	w := watch(t, tr)
	clock.waitForWaiter(t)
	fired := w.fired()
	if len(fired) != 1 {
		t.Fatalf("fired %v, want once", fired)
	}
	want := "http://admin:" + "xxxxx@127.0.0.1:1/ping?token=REDACTED&x=REDACTED"
	if fired[0]["Target"] != want || tr.Sample()["Target"] != want {
		t.Errorf("target = %v, sample %v, want %q", fired[0]["Target"], tr.Sample()["Target"], want)
	}
	for name, s := range map[string]string{
		"describe": tr.Describe(), "error": fmt.Sprint(fired[0]["Error"]), "target": fmt.Sprint(fired[0]["Target"]),
	} {
		if strings.Contains(s, "t0ken") || strings.Contains(s, "s3cret") {
			t.Errorf("%s leaks a secret: %q", name, s)
		}
	}
}
