// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
)

// tailscaleOptions put the hub on a tailnet with tsnet (docs/tailscale.md):
// off unless enabled.
type tailscaleOptions struct {
	enabled  bool
	hostname string
	// authKeyFile is --tailscale-authkey-file; authKey is HEARTH_TS_AUTHKEY.
	// The file wins: flags before the environment.
	authKeyFile string
	authKey     string
}

const (
	defaultTailscaleHostname = "hearth"
	// tailscaleDir is the tsnet state directory under the data dir: the
	// node key, so it is 0700 and never in a backup.
	tailscaleDir = "tailscale"
	// tailscaleStateFile is the file tsnet keeps the node's state in, in
	// tailscaleDir. A node that has one is logged in: it needs no auth key.
	tailscaleStateFile = "tailscaled.state"
	tailscaleKeyEnv    = "HEARTH_TS_AUTHKEY"
	tailscaleKeyFlag   = "--tailscale-authkey-file"
)

// errNoTailscale is what --tailscale fails with in a build without the
// tailscale build tag.
var errNoTailscale = errors.New("--tailscale: this build has no Tailscale; use the full release build " +
	"(https://github.com/gvart/hearth/releases) or build with -tags tailscale")

func addTailscaleFlags(cmd *cobra.Command, o *tailscaleOptions) {
	cmd.Flags().BoolVar(&o.enabled, "tailscale", false,
		"put the hub on your tailnet with its own Tailscale node: the UI over HTTPS at its MagicDNS name, "+
			"and agents on the tailnet enroll and connect over it (env HEARTH_TAILSCALE; auth key from env "+
			tailscaleKeyEnv+" or "+tailscaleKeyFlag+"; see docs/tailscale.md)")
	cmd.Flags().StringVar(&o.hostname, "tailscale-hostname", envOr("HEARTH_TAILSCALE_HOSTNAME", defaultTailscaleHostname),
		"name of the hub's node on the tailnet, its MagicDNS name <name>.<tailnet>.ts.net; give each hub of a cluster its own "+
			"(env HEARTH_TAILSCALE_HOSTNAME)")
	cmd.Flags().StringVar(&o.authKeyFile, "tailscale-authkey-file", os.Getenv("HEARTH_TS_AUTHKEY_FILE"),
		"file holding the Tailscale auth key, mode 0600; needed on the first start only, while the node is not "+
			"logged in yet (env HEARTH_TS_AUTHKEY_FILE)")
}

// fromEnv reads what the flags do not: HEARTH_TAILSCALE, unless --tailscale
// is given, and the auth key.
func (o *tailscaleOptions) fromEnv(cmd *cobra.Command) error {
	if v := os.Getenv("HEARTH_TAILSCALE"); v != "" && !cmd.Flags().Changed("tailscale") {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("HEARTH_TAILSCALE: %w", err)
		}
		o.enabled = b
	}
	o.authKey = os.Getenv(tailscaleKeyEnv)
	return nil
}

// tailnetConfig is what a tailnet node starts with: tailscaleOptions,
// checked and resolved.
type tailnetConfig struct {
	hostname string
	// dir is the tsnet state directory, 0700.
	dir string
	// authKey is empty for a node already logged in.
	authKey string
}

// hostnameLabel is a DNS label: the MagicDNS name's first part.
var hostnameLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// resolve checks o and returns the node's configuration, or nil when
// --tailscale is off. built is whether this build has Tailscale. It never
// puts the auth key into an error.
func (o tailscaleOptions) resolve(dataDir string, built bool) (*tailnetConfig, error) {
	if !o.enabled {
		if o.authKeyFile != "" {
			return nil, errors.New(tailscaleKeyFlag + " needs --tailscale")
		}
		return nil, nil
	}
	if !built {
		return nil, errNoTailscale
	}
	if !hostnameLabel.MatchString(o.hostname) {
		return nil, fmt.Errorf("--tailscale-hostname %q: want a DNS label: lower-case letters, digits and '-', at most 63", o.hostname)
	}
	dir := filepath.Join(dataDir, tailscaleDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("--tailscale: create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory, only its owner may enter it
		return nil, fmt.Errorf("--tailscale: %w", err)
	}
	key := o.authKey
	if o.authKeyFile != "" {
		s, err := readSecretFile(o.authKeyFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tailscaleKeyFlag, err)
		}
		key = s
	}
	if key == "" {
		if _, err := os.Stat(filepath.Join(dir, tailscaleStateFile)); err != nil {
			return nil, fmt.Errorf("--tailscale: no auth key: set %s or %s (needed on the first start only, "+
				"until %s holds the node's state)", tailscaleKeyEnv, tailscaleKeyFlag, dir)
		}
	}
	return &tailnetConfig{hostname: o.hostname, dir: dir, authKey: key}, nil
}

// tailnetNode is a node on a tailnet: tsnet in a build with the tailscale
// build tag (tailnet_tsnet.go).
type tailnetNode interface {
	// Up waits until the node runs, and returns its MagicDNS name and
	// addresses.
	Up(ctx context.Context) (dnsName string, ips []netip.Addr, err error)
	// Listen listens on the tailnet only.
	Listen(addr string) (net.Listener, error)
	// ListenTLS listens on the tailnet with a Let's Encrypt certificate for
	// the MagicDNS name, or fails if the tailnet has HTTPS certificates off.
	ListenTLS(addr string) (net.Listener, error)
	Close() error
}

// keyPattern matches a Tailscale auth key, whatever key it is.
var keyPattern = regexp.MustCompile(`tskey-[A-Za-z0-9_-]+`)

// redactKey removes the auth key from s, a log line or error of tsnet's.
func redactKey(s, key string) string {
	if key != "" {
		s = strings.ReplaceAll(s, key, "[redacted]")
	}
	return keyPattern.ReplaceAllString(s, "tskey-[redacted]")
}

// tailnet runs the hub's node on a tailnet and serves the hub there. It is
// the hub.Tailnet the API reads.
type tailnet struct {
	cfg tailnetConfig
	log *slog.Logger

	mu     sync.Mutex
	status hub.TailnetStatus
}

func newTailnet(cfg tailnetConfig, log *slog.Logger) *tailnet {
	return &tailnet{
		cfg: cfg, log: log,
		status: hub.TailnetStatus{State: hub.TailnetStarting, Hostname: cfg.hostname},
	}
}

func (t *tailnet) Status() hub.TailnetStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.status
	s.IPs = slices.Clone(s.IPs)
	return s
}

func (t *tailnet) update(f func(*hub.TailnetStatus)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f(&t.status)
}

// tailnetServe is what the hub serves on the tailnet.
type tailnetServe struct {
	// agentPort and httpPort are the hub's ports, which the tailnet mirrors.
	agentPort, httpPort string
	// agent serves agents and the UI over TLS on agentPort, with a
	// certificate from ca for hosts and the tailnet's names.
	agent http.Handler
	ca    *pki.CA
	hosts []string
	epoch string
	// web serves the UI, install.sh and the CA over plain HTTP on httpPort
	// (WireGuard encrypts it on the tailnet); ui the UI over HTTPS on 443.
	web, ui  http.Handler
	baseCtx  func(net.Listener) context.Context
	onStop   func()
	errorLog *log.Logger
}

// run brings node up and serves s on the tailnet until ctx is done. A
// tailnet that cannot be reached yet does not hold up the hub on the LAN:
// run waits for it. A node the tailnet refuses (a bad or expired auth key)
// ends in TailnetError, and the hub runs on without it.
func (t *tailnet) run(ctx context.Context, node tailnetNode, s tailnetServe) error {
	name, ips, err := node.Up(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return t.fail(ctx, err)
	}
	name = strings.TrimSuffix(name, ".")
	var names []string
	if name != "" {
		names = append(names, name)
	}
	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	names = append(names, ipStrs...)
	if len(names) == 0 {
		return t.fail(ctx, errors.New("the node has no name nor address"))
	}

	// The tailnet certificate names the hub's names and the tailnet's, and
	// follows a hub CA rotation like the hub's own.
	hosts := append(slices.Clone(s.hosts), names...)
	var cert atomic.Pointer[tls.Certificate]
	issue := func() error {
		c, err := s.ca.IssueHubServerCert(hosts, s.epoch, time.Now())
		if err != nil {
			return err
		}
		cert.Store(&c)
		return nil
	}
	if err := issue(); err != nil {
		return t.fail(ctx, fmt.Errorf("issue the tailnet certificate: %w", err))
	}
	s.ca.OnChange(func() {
		if err := issue(); err != nil {
			t.log.ErrorContext(ctx, "tailscale: issue the tailnet certificate for the hub CA", "err", err)
		}
	})

	g, gctx := errgroup.WithContext(ctx)
	newSrv := func(h http.Handler) *http.Server {
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ErrorLog: s.errorLog, BaseContext: s.baseCtx}
		if s.onStop != nil {
			srv.RegisterOnShutdown(s.onStop)
		}
		return srv
	}
	agentLn, err := node.Listen(":" + s.agentPort)
	if err != nil {
		return t.fail(ctx, fmt.Errorf("listen on :%s: %w", s.agentPort, err))
	}
	agentSrv := newSrv(s.agent)
	agentSrv.TLSConfig = hub.TLSConfigFunc(s.ca, cert.Load)
	g.Go(func() error { return serve(gctx, agentSrv, func() error { return agentSrv.ServeTLS(agentLn, "", "") }) })
	webLn, err := node.Listen(":" + s.httpPort)
	if err != nil {
		_ = agentLn.Close()
		return t.fail(ctx, fmt.Errorf("listen on :%s: %w", s.httpPort, err))
	}
	webSrv := newSrv(s.web)
	g.Go(func() error { return serve(gctx, webSrv, func() error { return webSrv.Serve(webLn) }) })

	agentURL := "https://" + net.JoinHostPort(names[0], s.agentPort)
	url, note := agentURL+"/", ""
	if uiLn, err := node.ListenTLS(":443"); err != nil {
		note = redactKey(err.Error(), t.cfg.authKey)
		t.log.WarnContext(ctx, "tailscale: no HTTPS on 443 with a tailnet certificate; the UI is at the hub CA's HTTPS port",
			"url", url, "err", note)
	} else {
		url = "https://" + names[0] + "/"
		uiSrv := newSrv(s.ui)
		g.Go(func() error { return serve(gctx, uiSrv, func() error { return uiSrv.Serve(uiLn) }) })
	}
	t.update(func(st *hub.TailnetStatus) {
		st.State, st.Error = hub.TailnetRunning, ""
		st.DNSName, st.IPs = name, ipStrs
		st.URL, st.AgentURL, st.HTTPSNote = url, agentURL, note
	})
	t.log.InfoContext(ctx, "tailscale: hub on the tailnet", "url", url, "agent_url", agentURL, "ips", ipStrs)
	// A listener the node closes ends the tailnet, never the hub.
	if err := g.Wait(); err != nil {
		return t.fail(ctx, err)
	}
	return nil
}

// fail records why the hub is not on the tailnet, without the auth key, and
// lets the hub run on: the tailnet never takes the hub on the LAN down.
func (t *tailnet) fail(ctx context.Context, err error) error {
	msg := redactKey(err.Error(), t.cfg.authKey)
	t.update(func(st *hub.TailnetStatus) { st.State, st.Error = hub.TailnetError, msg })
	t.log.ErrorContext(ctx, "tailscale: the hub runs without the tailnet", "err", msg)
	return nil
}

// portOr is port, or def if port is empty.
func portOr(port, def string) string {
	if port == "" {
		return def
	}
	return port
}
