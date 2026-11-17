// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// enrollDevice inserts a device as enrollment does: status unknown, with a
// name and labels that later facts must not overwrite.
func enrollDevice(t *testing.T, st *store.Store, id string) {
	t.Helper()
	now := time.Now()
	if err := st.Devices().Upsert(t.Context(), store.Device{
		ID: id, Name: id + "-name", Hostname: id, Labels: map[string]string{"room": "attic"},
		FirstSeen: now, LastSeen: now, Status: store.StatusUnknown,
	}); err != nil {
		t.Fatal(err)
	}
}

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.UnixMilli(1_700_000_000_000).UTC()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// syncBuffer collects log output from concurrent handlers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
