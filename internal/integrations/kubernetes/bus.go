// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import "sync"

// subscriberBuffer is how many notices a subscriber may fall behind before
// it is dropped.
const subscriberBuffer = 256

// bus fans notices out to subscribers without blocking: a subscriber that
// falls behind is dropped (its channel closed) and must resync.
type bus struct {
	mu   sync.Mutex
	subs map[chan Notice]struct{}
}

func (b *bus) subscribe() (<-chan Notice, func()) {
	ch := make(chan Notice, subscriberBuffer)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[chan Notice]struct{}{}
	}
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() { b.drop(ch) }
}

func (b *bus) publish(n Notice) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- n:
		default:
			delete(b.subs, ch)
			close(ch)
		}
	}
}

func (b *bus) drop(ch chan Notice) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
}
