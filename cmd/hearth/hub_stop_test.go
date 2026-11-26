// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/cluster"
)

// silentPeer accepts TCP connections and never answers on them, as a hub
// killed with its host gone looks to a member that got through.
func silentPeer(t *testing.T) string {
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

// TestHubStopsWithSilentPeers (#342): a hub restarted after the hub it
// joined was killed, its gossip seeds silent, returns within a few seconds
// of its context ending, with the masters' loops running (the LAN name,
// the removal of dead members, keep-masters).
func TestHubStopsWithSilentPeers(t *testing.T) {
	dataDir := t.TempDir()
	opts := hubOptions{
		dataDir: dataDir, listen: "127.0.0.1:0", httpListen: "127.0.0.1:0", hosts: []string{"127.0.0.1"},
		lanName: true,
		cluster: clusterOptions{nodeID: "h1", listen: "127.0.0.1:0", memberDeadAfter: time.Minute, keepMasters: 3},
	}
	run := func(seeds []string) time.Duration {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- runHub(ctx, opts, slog.New(slog.DiscardHandler)) }()
		for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			if cc, err := cluster.DialControl(dataDir); err == nil {
				_, err = cc.Status(t.Context())
				cc.Close()
				if err == nil {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("the hub did not answer on its control socket")
			}
		}
		if seeds != nil {
			// Into its first join of the silent seeds.
			time.Sleep(time.Second)
		}
		stopAt := time.Now()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("runHub = %v", err)
			}
			return time.Since(stopAt)
		case <-time.After(60 * time.Second):
			_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
			t.Fatal("the hub did not stop within 60 s of its context ending")
			return 0
		}
	}
	run(nil)
	// The members it learnt, now each silent.
	seeds := []string{silentPeer(t), silentPeer(t), silentPeer(t)}
	if err := os.WriteFile(filepath.Join(dataDir, cluster.StateDir, "gossip-seeds"),
		[]byte(strings.Join(seeds, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := run(seeds); d > 5*time.Second {
		t.Errorf("the hub stopped %v after its context ended, want < 5s", d)
	}
}
