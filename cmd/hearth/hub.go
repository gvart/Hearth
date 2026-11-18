// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/mcpserver"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

type hubOptions struct {
	dataDir    string
	listen     string
	httpListen string
	hosts      []string
	assetsDir  string
	// automationsDir holds the automation files; default <dataDir>/automations.
	automationsDir string
	// adminPassword is HEARTH_ADMIN_PASSWORD: it sets the admin password on a
	// hub that has none yet.
	adminPassword string
	// joinTokenEnv is HEARTH_JOIN_TOKEN, the preferred way to pass --join-token.
	joinTokenEnv string
	// prometheusURL is an existing Prometheus server to read device charts
	// from; empty means none.
	prometheusURL string
	// notifyConfig is the notification channels file; default
	// <dataDir>/notify.yaml if it exists.
	notifyConfig string
	// dangerousAutomations are the automations granted dangerous actions,
	// on top of those the policy file grants.
	dangerousAutomations []string
	// automationsDryRun sends every automation action to policy as a dry run.
	automationsDryRun bool
	// discoverSubnets are the subnets network discovery sweeps (or
	// "auto"); none turns discovery off.
	discoverSubnets []string
	// discoverInterval is the time between discovery scans.
	discoverInterval time.Duration
	cluster          clusterOptions
	// version is the binary's version, which install commands pin agents to.
	version string
}

func newHubCmd() *cobra.Command {
	opts := hubOptions{}
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Run the Hearth hub",
		Long: "Run the Hearth hub. On first start it creates its certificate authority and database\n" +
			"in the data dir. Agents enroll and connect over TLS on the listen address, which also\n" +
			"serves the web UI and JSON API over HTTPS with a certificate from the hub CA for the\n" +
			"--host names. The http-listen address serves the UI and API over plain HTTP, plus\n" +
			"/install.sh, /download/ and the CA certificate at /ca.crt (see docs/https.md).\n\n" +
			"If HEARTH_ADMIN_PASSWORD is set and no admin password is stored yet, it becomes the\n" +
			"admin password. Otherwise use `hearth admin set-password`.\n\n" +
			"Without cluster flags the hub runs standalone. --cluster forms a Raft cluster from this hub;\n" +
			"--join adds this hub to an existing one (see docs/design/ha-hub.md).\n\n" +
			"--prometheus-url points the hub at an existing Prometheus; device charts then show its\n" +
			"node-exporter data (see docs/prometheus.md).\n\n" +
			"--discover-subnet turns on network discovery: hosts without an agent show up as\n" +
			"unmanaged devices (see docs/discovery.md).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.adminPassword = os.Getenv("HEARTH_ADMIN_PASSWORD")
			opts.joinTokenEnv = os.Getenv("HEARTH_JOIN_TOKEN")
			opts.version = cmd.Root().Version
			if v := os.Getenv("HEARTH_DISCOVER_INTERVAL"); v != "" && !cmd.Flags().Changed("discover-interval") {
				d, err := time.ParseDuration(v)
				if err != nil {
					return fmt.Errorf("HEARTH_DISCOVER_INTERVAL: %w", err)
				}
				opts.discoverInterval = d
			}
			return runHub(cmd.Context(), opts, newLogger(cmd.ErrOrStderr()))
		},
	}
	cmd.Flags().StringVar(&opts.dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&opts.listen, "listen", ":"+defaultPort, "address to serve agents and the HTTPS web UI on (TLS)")
	cmd.Flags().StringVar(&opts.httpListen, "http-listen", ":"+defaultHTTPPort,
		"address to serve the web UI, API, installer and CA certificate on (plain HTTP)")
	cmd.Flags().StringSliceVar(&opts.hosts, "host", nil,
		"DNS name or IP agents and browsers use to reach the hub (its TLS certificate names); repeatable "+
			"(default: this hostname, localhost, 127.0.0.1, ::1)")
	cmd.Flags().StringVar(&opts.assetsDir, "assets-dir", "",
		"directory of release archives and checksums.txt to serve at /download/ for `install.sh --from-hub`")
	cmd.Flags().StringVar(&opts.prometheusURL, "prometheus-url", os.Getenv("HEARTH_PROMETHEUS_URL"),
		"Prometheus server to read device charts from, e.g. http://prometheus.lan:9090 (env HEARTH_PROMETHEUS_URL)")
	cmd.Flags().StringVar(&opts.automationsDir, "automations-dir", "",
		"directory of automation YAML files, reloaded when they change (default <data-dir>/automations)")
	cmd.Flags().StringVar(&opts.notifyConfig, "notify-config", os.Getenv("HEARTH_NOTIFY_CONFIG"),
		"file of notification channels (ntfy, Telegram) for notify actions (env HEARTH_NOTIFY_CONFIG; default <data-dir>/notify.yaml if it exists; see docs/notifications.md)")
	cmd.Flags().StringArrayVar(&opts.dangerousAutomations, "allow-dangerous-automation", nil,
		"id of an automation allowed to take dangerous actions, such as exec, without approval; repeatable, "+
			"added to dangerous_automations of <data-dir>/policy.yaml (default: none)")
	cmd.Flags().BoolVar(&opts.automationsDryRun, "automations-dry-run", false,
		"run automations as dry runs: each action's policy decision is audited, and no action runs")
	cmd.Flags().StringSliceVar(&opts.discoverSubnets, "discover-subnet", splitList(os.Getenv("HEARTH_DISCOVER_SUBNETS")),
		"IPv4 subnet to discover hosts on with an ARP sweep and mDNS, e.g. 192.168.1.0/24, or \"auto\" for the hub's own LANs; "+
			"repeatable (env HEARTH_DISCOVER_SUBNETS, comma-separated; default: off; see docs/discovery.md)")
	cmd.Flags().DurationVar(&opts.discoverInterval, "discover-interval", discovery.DefaultInterval,
		"time between network discovery scans (env HEARTH_DISCOVER_INTERVAL)")
	addClusterFlags(cmd, &opts.cluster)
	return cmd
}

// splitList splits a comma-separated environment value.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func runHub(ctx context.Context, opts hubOptions, log *slog.Logger) error {
	if opts.assetsDir != "" {
		if info, err := os.Stat(opts.assetsDir); err != nil || !info.IsDir() {
			return fmt.Errorf("--assets-dir %s is not a directory", opts.assetsDir)
		}
	}
	var prom *prometheus.Reader
	if opts.prometheusURL != "" {
		c, err := prometheus.NewClient(opts.prometheusURL, nil)
		if err != nil {
			return fmt.Errorf("--prometheus-url: %w", err)
		}
		prom = prometheus.NewReader(c)
	}
	if err := os.MkdirAll(opts.dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	var subnets []netip.Prefix
	var autoSubnets bool
	if len(opts.discoverSubnets) > 0 {
		var err error
		if subnets, autoSubnets, err = discovery.ParseSubnets(opts.discoverSubnets); err != nil {
			return fmt.Errorf("--discover-subnet: %w", err)
		}
	}
	polCfg, err := loadPolicyConfig(opts.dataDir)
	if err != nil {
		return err
	}
	polCfg.DangerousAutomations = append(polCfg.DangerousAutomations, opts.dangerousAutomations...)
	hosts := opts.hosts
	if len(hosts) == 0 {
		hosts = []string{hostnameOr("localhost"), "localhost", "127.0.0.1", "::1"}
	}
	var agentPort string
	if _, port, err := net.SplitHostPort(opts.listen); err == nil && port != "0" {
		agentPort = port
	}
	// A Raft node that fails to apply a committed write stops the hub.
	fatal := make(chan error, 1)
	var (
		st   *store.Store
		ca   *pki.CA
		node *cluster.Node
	)
	if opts.cluster.clustered(opts.dataDir) {
		// Agents and other hubs reach this hub by its first --host name.
		var agentURL string
		if agentPort != "" {
			agentURL = "https://" + net.JoinHostPort(hosts[0], agentPort)
		}
		st, ca, node, err = startClusterNode(ctx, opts, log, func(err error) { fatal <- err }, agentURL, agentPort)
		if err != nil {
			return err
		}
		defer st.Close()
		defer func() { _ = node.Shutdown() }() // before the store closes
	} else {
		st, err = store.Open(ctx, filepath.Join(opts.dataDir, dbFile))
		if err != nil {
			return err
		}
		defer st.Close()
		if ca, err = pki.LoadOrCreateCA(opts.dataDir, time.Now()); err != nil {
			return err
		}
	}
	now := time.Now()
	serverCert, err := ca.IssueServerCert(hosts, now)
	if err != nil {
		return err
	}

	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), polCfg)
	if node == nil {
		if err := ensureAdminPassword(ctx, st, pol, opts, log); err != nil {
			return err
		}
	}
	reg := hub.NewRegistry(hub.RegistryConfig{Store: st, Log: log, Replicated: node != nil})
	agents := hub.NewAgents(st.Devices())
	kube, err := newKubeManager(st, ca, pol, log)
	if err != nil {
		return err
	}
	notifier, err := loadNotifier(opts, log)
	if err != nil {
		return err
	}
	if err := notifyApprovals(pol, polCfg.ApprovalNotify, st, notifier, hosts[0], agentPort, log); err != nil {
		return err
	}
	// stopping ends agent streams and /events subscriptions as soon as either
	// server begins shutting down, so Shutdown waits only on ordinary requests
	// and agents see a clean end of stream and reconnect at once.
	stopping, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	cfg := hub.Config{
		Store:             st,
		CA:                ca,
		Policy:            pol,
		Log:               log,
		HeartbeatInterval: hub.DefaultHeartbeatInterval,
		Registry:          reg,
		AgentHosts:        hosts,
		AgentPort:         agentPort,
		Stopping:          stopping,
		Prometheus:        prom,
		Agents:            agents,
		Kube:              kube,
		Notify:            notifier,
		Version:           opts.version,
	}
	if exe, err := os.Executable(); err == nil {
		cfg.VerifyPassword = hub.ChildVerifier(exe)
	} else {
		log.WarnContext(ctx, "cannot find own binary: verifying login passwords in-process", "err", err)
	}
	// ready is closed once a clustered hub has caught up with the cluster.
	ready := make(chan struct{})
	if node != nil {
		cfg.Leadership = node
		cfg.Ready = ready
	}
	if _, port, err := net.SplitHostPort(opts.httpListen); err == nil && port != "0" {
		cfg.HTTPPort = port
	}
	errLog := slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	baseCtx := func(net.Listener) context.Context { return ctx }
	// The UI and API, served on both listeners. Over TLS they share the agent
	// port, so browsers get HTTPS with the hub CA (see docs/https.md).
	webH := hub.NewHTTPHandler(cfg)
	uiMux := http.NewServeMux()
	uiMux.Handle("/", webH)
	uiMux.Handle("GET /api/v1/events", hub.EndOnStop(stopping, webH))
	automationsDir := opts.automationsDir
	if automationsDir == "" {
		automationsDir = filepath.Join(opts.dataDir, "automations")
	}
	uiMux.Handle(mcpserver.Path, hub.EndOnStop(stopping, mcpserver.Handler(mcpserver.Config{
		Devices: st.Devices(), Live: reg.Live, Tokens: st.MCPTokens(), Policy: pol, Agents: agents, Kube: kube,
		Metrics: hub.AutomationMetrics(st, prom), AutomationsDir: automationsDir, Version: opts.version, Log: log,
	})))
	var tlsWeb http.Handler = uiMux
	if node != nil {
		// ClusterService is served over TLS only: Promote authenticates
		// hubs by their client certificate.
		m := http.NewServeMux()
		m.Handle("/", uiMux)
		m.Handle(cluster.NewJoinServer(node, st, ca, pol, log).Handler())
		tlsWeb = m
	}
	agentSrv := &http.Server{
		Handler:           hub.NewTLSHandler(cfg, tlsWeb),
		TLSConfig:         hub.TLSConfig(ca, serverCert),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          errLog,
		BaseContext:       baseCtx,
	}
	agentSrv.RegisterOnShutdown(stop)
	// install.sh, downloads and the CA stay on plain HTTP only: a new device
	// does not trust the hub CA yet.
	webMux := http.NewServeMux()
	webMux.Handle("/", uiMux)
	hub.RegisterInstallRoutes(webMux, opts.assetsDir)
	hub.RegisterCARoute(webMux, ca.Cert())
	// No WriteTimeout: /api/v1/events is a long-lived stream.
	webSrv := &http.Server{
		Handler:           webMux,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          errLog,
		BaseContext:       baseCtx,
	}
	webSrv.RegisterOnShutdown(stop)
	lc := &net.ListenConfig{}
	agentLn, err := lc.Listen(ctx, "tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", opts.listen, err)
	}
	webLn, err := lc.Listen(ctx, "tcp", opts.httpListen)
	if err != nil {
		_ = agentLn.Close()
		return fmt.Errorf("listen on %s: %w", opts.httpListen, err)
	}
	fp := ca.Fingerprint()
	logAttrs := []any{
		"addr", agentLn.Addr().String(), "http_addr", webLn.Addr().String(),
		"hosts", hosts, "data_dir", opts.dataDir, "ca_fingerprint", hex.EncodeToString(fp[:]),
	}
	if node != nil {
		logAttrs = append(logAttrs, "node_id", node.ID(), "raft_addr", node.Addr())
	}
	logAttrs = append(logAttrs, "prometheus", prom != nil)
	log.InfoContext(ctx, "hub listening", logAttrs...)

	kinds := automation.Builtin(log)
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{
		Devices: hub.AutomationDevices(reg),
		Metrics: hub.AutomationMetrics(st, prom),
		Probers: agents,
		Policy:  pol,
		Log:     log,
	}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{Agents: agents, Notifier: notifier, Kube: kube}))
	automations := automation.New(automation.Config{
		Dir:    automationsDir,
		Kinds:  kinds,
		Policy: pol,
		Runs:   st.AutomationRuns(),
		Log:    log,
		DryRun: opts.automationsDryRun,
	})

	var scanner *discovery.Scanner
	if len(subnets) > 0 || autoSubnets {
		scanner = discovery.New(discovery.Config{
			Subnets: subnets, Auto: autoSubnets, Interval: opts.discoverInterval,
			Hosts: st.NetworkHosts(), Policy: pol, Events: reg, Log: log.With("component", "discovery"),
		})
	}

	g, gctx := errgroup.WithContext(ctx)
	if node == nil {
		g.Go(func() error { return reg.Run(gctx) })
		g.Go(func() error { return automations.Run(gctx) })
		if scanner != nil {
			g.Go(func() error { return scanner.Run(gctx) })
		}
	}
	// Every hub of a cluster watches the Kubernetes clusters itself.
	g.Go(func() error { return kube.Run(gctx) })
	g.Go(func() error { return serve(gctx, agentSrv, func() error { return agentSrv.ServeTLS(agentLn, "", "") }) })
	g.Go(func() error { return serve(gctx, webSrv, func() error { return webSrv.Serve(webLn) }) })
	if node != nil {
		// Followers publish device events from the entries they apply.
		node.ObserveApplies(reg)
		// Presence, automations and network discovery run on the leader
		// only and follow leadership.
		changed, automationsChanged, discoveryChanged := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
		node.OnLeaderChange(func(cluster.LeaderInfo) {
			for _, c := range []chan struct{}{changed, automationsChanged, discoveryChanged} {
				select {
				case c <- struct{}{}:
				default:
				}
			}
		})
		g.Go(func() error { return reg.RunReplicated(gctx, node, changed) })
		g.Go(func() error {
			return automation.RunWhileLeading(gctx, node, automationsChanged, log, automations.Run)
		})
		if scanner != nil {
			g.Go(func() error {
				return automation.RunWhileLeading(gctx, node, discoveryChanged, log.With("component", "discovery"), scanner.Run)
			})
		}
		g.Go(func() error {
			if node.WaitReady(gctx) != nil {
				return nil
			}
			close(ready)
			log.InfoContext(gctx, "caught up with the cluster")
			// After catching up, so a new member sees the cluster's password
			// and does not replace it.
			if err := ensureAdminPassword(gctx, st, pol, opts, log); err != nil {
				log.ErrorContext(gctx, "HEARTH_ADMIN_PASSWORD not applied", "err", err)
			}
			node.Announce(gctx)
			node.RecordNodeCert(gctx)
			return nil
		})
		g.Go(func() error {
			return cluster.ServeControl(gctx, opts.dataDir, node, log)
		})
		g.Go(func() error { return promoteUntilVoter(gctx, node, opts.dataDir, log) })
		g.Go(func() error {
			select {
			case err := <-fatal:
				return err
			case <-gctx.Done():
				return nil
			}
		})
	}
	err = g.Wait()
	log.InfoContext(ctx, "hub stopped")
	return err
}

// newKubeManager returns the manager of adopted Kubernetes clusters. Their
// kubeconfigs are sealed with a key derived from the hub CA key, which every
// hub of a cluster holds.
func newKubeManager(st *store.Store, ca *pki.CA, pol *policy.Engine, log *slog.Logger) (*kubernetes.Manager, error) {
	secret, err := ca.KeyDER()
	if err != nil {
		return nil, err
	}
	sealer, err := kubernetes.NewSealer(secret)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewManager(kubernetes.Config{Store: st, Sealer: sealer, Policy: pol, Log: log}), nil
}

// serve runs srv until ctx is done, then shuts it down gracefully (forcibly
// after 5 s). A serve error that is not a shutdown ends the hub.
func serve(ctx context.Context, srv *http.Server, run func() error) error {
	errc := make(chan error, 1)
	go func() { errc <- run() }()
	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// ensureAdminPassword sets the admin password from HEARTH_ADMIN_PASSWORD if
// none is stored yet, and otherwise tells the operator how to set one. It never
// logs the password.
func ensureAdminPassword(ctx context.Context, st *store.Store, pol *policy.Engine, opts hubOptions, log *slog.Logger) error {
	_, err := st.Admin().PasswordHash(ctx)
	switch {
	case err == nil:
		if opts.adminPassword != "" {
			log.InfoContext(ctx, "admin password already set; ignoring HEARTH_ADMIN_PASSWORD")
		}
		return nil
	case !errors.Is(err, store.ErrNotFound):
		return err
	case opts.adminPassword == "":
		log.WarnContext(ctx, "admin password not set: web login is disabled until you run "+
			"`hearth admin set-password --data-dir "+opts.dataDir+"` or restart with HEARTH_ADMIN_PASSWORD set")
		return nil
	}
	if err := hub.SetAdminPassword(ctx, st, pol, "env:HEARTH_ADMIN_PASSWORD", opts.adminPassword); err != nil {
		return fmt.Errorf("set admin password from HEARTH_ADMIN_PASSWORD: %w", err)
	}
	log.InfoContext(ctx, "admin password set from HEARTH_ADMIN_PASSWORD")
	return nil
}

// loadNotifier reads the notification channels file: --notify-config, or
// <data-dir>/notify.yaml if it exists. Without one the hub has no channels.
// It logs channel names only, never their addresses or credentials.
// notifyApprovals sends every action pol holds to the policy file's
// approval_notify channel, with an approval link based at its url or, by
// default, the hub's HTTPS address for host.
func notifyApprovals(pol *policy.Engine, cfg policy.ApprovalNotify, st *store.Store, n *notify.Notifier,
	host, port string, log *slog.Logger,
) error {
	if cfg.Channel == "" {
		return nil
	}
	if !n.Has(cfg.Channel) {
		return fmt.Errorf("policy config: approval_notify.channel %q is not in the notification channels file", cfg.Channel)
	}
	base := cfg.URL
	if base == "" {
		if port == "" {
			port = defaultPort
		}
		base = "https://" + net.JoinHostPort(host, port)
	}
	pol.OnHeld(hub.NewApprovalNotifier(hub.ApprovalNotifierConfig{
		Links: st.ApprovalLinks(), Notifier: n, Channel: cfg.Channel, BaseURL: base, Log: log,
	}))
	log.Info("held actions are notified", "channel", cfg.Channel, "link_base", base)
	return nil
}

func loadNotifier(opts hubOptions, log *slog.Logger) (*notify.Notifier, error) {
	path := opts.notifyConfig
	if path == "" {
		path = filepath.Join(opts.dataDir, "notify.yaml")
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			return &notify.Notifier{}, nil
		}
	}
	n, err := notify.Load(path)
	if err != nil {
		return nil, fmt.Errorf("--notify-config: %w", err)
	}
	if notify.Exposed(path) {
		log.Warn("notification channels file is readable by other users, and holds credentials: chmod 600 it", "path", path)
	}
	names := []string{}
	for _, c := range n.Channels() {
		names = append(names, c.Name)
	}
	log.Info("notification channels loaded", "path", path, "channels", names)
	return n, nil
}
