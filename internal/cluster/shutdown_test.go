// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// blackhole accepts TCP connections and never answers on them, as a member
// killed with its host gone looks to a dialer that got through: the TLS
// handshake waits until its timeout.
func blackhole(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// TestAPNodeStopsWithSilentSeeds: a member whose seeds and peers no longer
// answer (#342: the first hub killed) stops within a few seconds of its
// context ending, with the gossip's default timeouts: no dial or join to a
// silent peer holds the stop up.
func TestAPNodeStopsWithSilentSeeds(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tn := prepareAPTestNode(t, ca, apSpec{id: "a", roles: storageMaster, allowed: storageMaster})
	ca, err = pki.LoadCA(tn.dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seeds := []string{blackhole(t), blackhole(t), blackhole(t)}
	node, err := NewAPNode(t.Context(), APConfig{
		DataDir: tn.dir, NodeID: tn.id, CA: ca, Allowed: tn.allowed,
		Listen: ln.Addr().String(), Listener: ln, Advertise: ln.Addr().String(), Seeds: seeds,
		Replicas: 2, Log: testLogger(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(tn.dir, "hearth.db")
	storetest.Migrated(t, dbPath)
	st, err := store.Open(t.Context(), dbPath, node.StoreOptions()...)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := node.Bind(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- node.Run(ctx) }()
	// Into the first join of the seeds, each a silent peer.
	time.Sleep(time.Second)
	stopAt := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		if d := time.Since(stopAt); d > 5*time.Second {
			t.Errorf("Run returned %v after its context ended, want < 5s", d)
		}
	case <-time.After(30 * time.Second):
		_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
		t.Fatal("Run did not return within 30 s of its context ending")
	}
}
