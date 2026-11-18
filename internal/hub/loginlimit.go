// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	// verifyWait is how long a login waits for the password verification
	// slot before it is answered 503 busy.
	verifyWait = 10 * time.Second
	// loginBurst and loginEvery set the per-client login rate: a burst of
	// loginBurst attempts, then one more every loginEvery.
	loginBurst = 5
	loginEvery = 12 * time.Second
	// maxLoginClients bounds the limiter's table; past it, clients whose
	// bucket has refilled are dropped.
	maxLoginClients = 1024
)

var errVerifyBusy = errors.New("password verification busy")

// verifyGate runs one password verification at a time. argon2 is CPU and
// memory bound: on a hub with one slow or quota-limited core, verifications
// side by side starve Raft's heartbeats and cost the hub its leadership.
type verifyGate chan struct{}

func newVerifyGate() verifyGate { return make(verifyGate, 1) }

// do runs fn once it holds the slot. It gives up with errVerifyBusy after
// wait, or with ctx's error when ctx ends first.
func (g verifyGate) do(ctx context.Context, wait time.Duration, fn func()) error {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case g <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return errVerifyBusy
	}
	defer func() { <-g }()
	fn()
	return nil
}

// loginLimiter is a token bucket per client address.
type loginLimiter struct {
	now   func() time.Time
	burst float64
	every time.Duration

	mu      sync.Mutex
	clients map[string]*loginBucket
}

type loginBucket struct {
	tokens float64
	at     time.Time
}

func newLoginLimiter(now func() time.Time, burst int, every time.Duration) *loginLimiter {
	return &loginLimiter{now: now, burst: float64(burst), every: every, clients: map[string]*loginBucket{}}
}

// allow takes a token for client. When there is none it reports how long
// until there is one.
func (l *loginLimiter) allow(client string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.clients[client]
	if !ok {
		if len(l.clients) >= maxLoginClients {
			l.prune(now)
		}
		b = &loginBucket{tokens: l.burst, at: now}
		l.clients[client] = b
	}
	l.refill(b, now)
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) * float64(l.every))
	}
	b.tokens--
	return true, 0
}

func (l *loginLimiter) refill(b *loginBucket, now time.Time) {
	if el := now.Sub(b.at); el > 0 {
		b.tokens = min(l.burst, b.tokens+float64(el)/float64(l.every))
		b.at = now
	}
}

// prune drops clients whose bucket is full again: forgetting them changes
// nothing. If none is, it drops all, so the table stays bounded.
func (l *loginLimiter) prune(now time.Time) {
	for k, b := range l.clients {
		if l.refill(b, now); b.tokens >= l.burst {
			delete(l.clients, k)
		}
	}
	if len(l.clients) >= maxLoginClients {
		clear(l.clients)
	}
}
