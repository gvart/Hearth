// SPDX-License-Identifier: AGPL-3.0-only

//go:build tailscale

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

// tailscaleBuilt is whether this build has Tailscale: the release builds
// do (the tailscale build tag in .goreleaser.yaml and Taskfile.yml).
const tailscaleBuilt = true

// tsnetNode is a tailnetNode on tsnet: a Tailscale node in the hub's own
// process, with a userspace network stack. The agent never starts one.
type tsnetNode struct {
	s   *tsnet.Server
	dir string
}

// newTailnetNode starts the hub's node. It uploads no logs to Tailscale, and
// logs tsnet's own lines at debug level, without the auth key.
func newTailnetNode(cfg tailnetConfig, log *slog.Logger) (tailnetNode, error) {
	envknob.SetNoLogsNoSupport()
	s := &tsnet.Server{
		Dir:      cfg.dir,
		Hostname: cfg.hostname,
		AuthKey:  cfg.authKey,
		Logf: func(format string, args ...any) {
			log.Debug(redactKey(fmt.Sprintf(format, args...), cfg.authKey))
		},
		UserLogf: func(format string, args ...any) {
			log.Info(redactKey(fmt.Sprintf(format, args...), cfg.authKey))
		},
	}
	if err := s.Start(); err != nil {
		return nil, fmt.Errorf("--tailscale: %s", redactKey(err.Error(), cfg.authKey))
	}
	return &tsnetNode{s: s, dir: cfg.dir}, nil
}

// Up waits for the node to run. A node that needs an interactive login
// (no auth key on its first start, or a node key that expired) fails here
// rather than waiting for ever: tsnet would only print a login URL.
func (n *tsnetNode) Up(ctx context.Context) (string, []netip.Addr, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		st  *ipnstate.Status
		err error
	}
	up := make(chan result, 1)
	go func() {
		st, err := n.s.Up(ctx)
		up <- result{st, err}
	}()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case r := <-up:
			if r.err != nil {
				return "", nil, r.err
			}
			var name string
			if r.st.Self != nil {
				name = r.st.Self.DNSName
			}
			return name, r.st.TailscaleIPs, nil
		case <-tick.C:
			if lc, err := n.s.LocalClient(); err == nil {
				if st, err := lc.StatusWithoutPeers(ctx); err == nil && st.BackendState == ipn.NeedsLogin.String() && st.AuthURL != "" {
					return "", nil, fmt.Errorf("the node is not logged in to the tailnet (no auth key on its first start, or its key expired): "+
						"restart the hub with a new auth key in %s or %s, after removing %s if it holds an old node",
						tailscaleKeyEnv, tailscaleKeyFlag, n.dir)
				}
			}
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
	}
}

func (n *tsnetNode) Listen(addr string) (net.Listener, error)    { return n.s.Listen("tcp", addr) }
func (n *tsnetNode) ListenTLS(addr string) (net.Listener, error) { return n.s.ListenTLS("tcp", addr) }
func (n *tsnetNode) Close() error                                { return n.s.Close() }
