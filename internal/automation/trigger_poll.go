// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"time"
)

// pollState is what one check of a poller found.
type pollState int

const (
	stateGood pollState = iota
	stateBad
	// stateUnknown is a check that could not run (a check from a device
	// whose agent is offline): it changes nothing, neither ending a bad
	// spell nor counting towards one.
	stateUnknown
)

// poller checks a state every interval and fires once the state has been bad
// for the hold duration. It fires once per bad spell: it fires again only
// after a good check.
type poller struct {
	clock Clock
	every time.Duration
	hold  time.Duration
	// bad reports the state now, and if it is bad what a firing tells
	// about it.
	bad func(ctx context.Context) (map[string]any, pollState)
}

// watch runs the first check at once, then one every p.every, until ctx is
// done.
func (p poller) watch(ctx context.Context, fire FireFunc) error {
	var since time.Time // start of the current bad spell; zero when good
	fired := false
	for {
		data, state := p.bad(ctx)
		if ctx.Err() != nil {
			// A check cut short by the stop is not a failure.
			return nil
		}
		switch state {
		case stateBad:
			now := p.clock.Now()
			if since.IsZero() {
				since = now
			}
			if !fired && now.Sub(since) >= p.hold {
				fire(data)
				fired = true
			}
		case stateGood:
			since, fired = time.Time{}, false
		case stateUnknown:
		}
		select {
		case <-ctx.Done():
			return nil
		case <-p.clock.After(p.every):
		}
	}
}

// pollTiming are the fields every polling trigger has.
type pollTiming struct {
	Every   time.Duration
	For     time.Duration
	Timeout time.Duration
}

// minEvery keeps a polling trigger from hammering what it checks.
const minEvery = time.Second

// check fills in the defaults and validates t. A zero timeout defaults to
// the interval, at most defaultTimeout.
func (t *pollTiming) check(defaultEvery time.Duration) error {
	if t.Every == 0 {
		t.Every = defaultEvery
	}
	if t.Every < minEvery {
		return errors.New("every must be at least 1s")
	}
	if t.For < 0 {
		return errors.New("for must not be negative")
	}
	if t.Timeout == 0 {
		t.Timeout = min(t.Every, defaultTimeout)
	}
	if t.Timeout < 0 {
		return errors.New("timeout must not be negative")
	}
	return nil
}

// defaultTimeout bounds one check or query.
const defaultTimeout = 5 * time.Second

// forText describes a hold duration for a dry run.
func forText(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return " for " + d.String()
}
