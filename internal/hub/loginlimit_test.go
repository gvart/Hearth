// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyGateOneAtATime(t *testing.T) {
	g := newVerifyGate()
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			err := g.do(t.Context(), time.Minute, func() {
				n := running.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				running.Add(-1)
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if p := peak.Load(); p != 1 {
		t.Errorf("peak concurrency = %d, want 1", p)
	}
}

// hold takes g's slot until the returned func is called.
func hold(t *testing.T, g verifyGate) func() {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	go func() { _ = g.do(context.Background(), time.Minute, func() { close(in); <-out }) }()
	<-in
	return func() { close(out) }
}

func TestVerifyGateWaiting(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		g := newVerifyGate()
		defer hold(t, g)()
		ran := false
		if err := g.do(t.Context(), 20*time.Millisecond, func() { ran = true }); !errors.Is(err, errVerifyBusy) {
			t.Fatalf("err = %v, want errVerifyBusy", err)
		}
		if ran {
			t.Error("fn ran without the slot")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		g := newVerifyGate()
		defer hold(t, g)()
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(10*time.Millisecond, cancel)
		if err := g.do(ctx, time.Minute, func() { t.Error("fn ran without the slot") }); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("released", func(t *testing.T) {
		g := newVerifyGate()
		release := hold(t, g)
		time.AfterFunc(10*time.Millisecond, release)
		ran := false
		if err := g.do(t.Context(), time.Minute, func() { ran = true }); err != nil || !ran {
			t.Fatalf("err = %v, ran = %v", err, ran)
		}
		// The slot is free again.
		if err := g.do(t.Context(), time.Millisecond, func() {}); err != nil {
			t.Fatal(err)
		}
	})
}

// limiter is a 3-attempt burst refilling one every 10s, on c.
func testLimiter(c *fakeClock) *loginLimiter { return newLoginLimiter(c.Now, 3, 10*time.Second) }

func allowed(l *loginLimiter, ip string) bool {
	ok, _ := l.allow(ip)
	return ok
}

func TestLoginLimiter(t *testing.T) {
	c := newFakeClock()
	l := testLimiter(c)
	for i := range 3 {
		if !allowed(l, "10.0.0.1") {
			t.Fatalf("attempt %d within the burst refused", i+1)
		}
	}
	ok, wait := l.allow("10.0.0.1")
	if ok || wait != 10*time.Second {
		t.Fatalf("burst exceeded: ok = %v, wait = %v, want refused, 10s", ok, wait)
	}
	if !allowed(l, "10.0.0.2") {
		t.Error("another client shares the first one's bucket")
	}
	c.Advance(4 * time.Second)
	if ok, wait := l.allow("10.0.0.1"); ok || wait != 6*time.Second {
		t.Fatalf("after 4s: ok = %v, wait = %v, want refused, 6s", ok, wait)
	}
	c.Advance(6 * time.Second)
	if !allowed(l, "10.0.0.1") {
		t.Fatal("a token refilled after 10s was refused")
	}
	if allowed(l, "10.0.0.1") {
		t.Fatal("one refilled token allowed two attempts")
	}
	c.Advance(time.Hour)
	for i := range 3 {
		if !allowed(l, "10.0.0.1") {
			t.Fatalf("after an hour, attempt %d refused", i+1)
		}
	}
	if allowed(l, "10.0.0.1") {
		t.Error("an idle hour refilled past the burst")
	}
}

func TestLoginLimiterBounded(t *testing.T) {
	c := newFakeClock()
	l := testLimiter(c)
	for i := range maxLoginClients {
		l.allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	// Every bucket refills: the next new client prunes them all.
	c.Advance(time.Minute)
	l.allow("192.0.2.1")
	if n := len(l.clients); n != 1 {
		t.Errorf("clients = %d after prune, want 1", n)
	}
	// None refilled: the table is cleared rather than grown.
	for i := range maxLoginClients + 10 {
		l.allow(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
	}
	if n := len(l.clients); n > maxLoginClients {
		t.Errorf("clients = %d, want at most %d", n, maxLoginClients)
	}
}

func TestAPILoginRateLimited(t *testing.T) {
	f := newAPIFixture(t, true)
	for i := range loginBurst {
		if resp := f.login(t, "nope-nope-nope"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, resp.StatusCode)
		}
	}
	resp := f.login(t, testPassword) // even the right password
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if e := decode[ErrorJSON](t, resp); e.Code != "rate_limited" {
		t.Errorf("error = %+v", e)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "12" {
		t.Errorf("Retry-After = %q, want 12", ra)
	}
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			t.Error("rate-limited login set a session cookie")
		}
	}
}

func TestAPILoginBusy(t *testing.T) {
	f := newAPIFixture(t, true)
	f.api.verifyWait = 20 * time.Millisecond
	defer hold(t, f.api.verify)()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/login",
		strings.NewReader(`{"password":"`+testPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.api.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}
	var e ErrorJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Code != "busy" {
		t.Errorf("error = %+v (%v)", e, err)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("busy login set a cookie")
	}
}
