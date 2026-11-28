// SPDX-License-Identifier: AGPL-3.0-only

//go:build tailscale

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"tailscale.com/envknob"
	"tailscale.com/tsnet"
)

// tailscaleBuilt is whether this build has Tailscale: the release builds
// do (the tailscale build tag in .goreleaser.yaml and Taskfile.yml).
const tailscaleBuilt = true

// tsnetNode is a tailnetNode on tsnet: a Tailscale node in the hub's own
// process, with a userspace network stack. The agent never starts one.
type tsnetNode struct{ s *tsnet.Server }

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
	return &tsnetNode{s: s}, nil
}

func (n *tsnetNode) Up(ctx context.Context) (string, []netip.Addr, error) {
	st, err := n.s.Up(ctx)
	if err != nil {
		return "", nil, err
	}
	var name string
	if st.Self != nil {
		name = st.Self.DNSName
	}
	return name, st.TailscaleIPs, nil
}

func (n *tsnetNode) Listen(addr string) (net.Listener, error)    { return n.s.Listen("tcp", addr) }
func (n *tsnetNode) ListenTLS(addr string) (net.Listener, error) { return n.s.ListenTLS("tcp", addr) }
func (n *tsnetNode) Close() error                                { return n.s.Close() }
