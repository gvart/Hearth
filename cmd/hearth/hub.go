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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/integrations/beszel"
	"github.com/gvart/hearth/internal/integrations/esphome"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/openwrt"
	"github.com/gvart/hearth/internal/integrations/opnsense"
	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/integrations/proxmox"
	"github.com/gvart/hearth/internal/integrations/talos"
	"github.com/gvart/hearth/internal/integrations/unifi"
	"github.com/gvart/hearth/internal/mcpserver"
	"github.com/gvart/hearth/internal/metrics"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

type hubOptions struct {
	dataDir    string
	listen     string
	httpListen string
	// agentLn and webLn, if set, are listeners already bound to listen and
	// httpListen, which the hub serves on and closes. Tests bind port 0
	// and pass them, so no other process can take the port first.
	agentLn, webLn net.Listener
	hosts          []string
	// lanName announces discovery.LANName over mDNS from one master and
	// names it in the certificate; off with --no-lan-name (and in tests).
	lanName   bool
	assetsDir string
	// automationsDir holds the automation files; default <dataDir>/automations.
	automationsDir string
	// runbooksDir holds the runbook files; default <dataDir>/runbooks.
	runbooksDir string
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
	// newDeviceAlerts is the notification channel the built-in new-device
	// alert automation sends to; empty leaves it off.
	newDeviceAlerts string
	// piholeURL is a Pi-hole v6 whose network table and DHCP leases are
	// imported; empty means none. Its password is HEARTH_PIHOLE_PASSWORD
	// (piholePassword) or the file piholePasswordFile.
	piholeURL          string
	piholePassword     string
	piholePasswordFile string
	// netalertxURL is a NetAlertX API server whose devices are imported;
	// empty means none. Its API token is HEARTH_NETALERTX_TOKEN
	// (netalertxToken) or the file netalertxTokenFile.
	netalertxURL       string
	netalertxToken     string
	netalertxTokenFile string
	// beszelURL is a Beszel hub whose systems the hub reads; empty means
	// none. It logs in as beszelEmail with HEARTH_BESZEL_PASSWORD
	// (beszelPassword) or the file beszelPasswordFile.
	beszelURL          string
	beszelEmail        string
	beszelPassword     string
	beszelPasswordFile string
	// talosconfig is a talosconfig file whose nodes the hub reads through
	// the Talos API; empty means none. talosContext picks its context (the
	// current one if empty) and talosNodes replaces the context's nodes.
	talosconfig  string
	talosContext string
	talosNodes   []string
	// dhcpLeases are DHCP lease files (dnsmasq, ISC dhcpd) to import.
	dhcpLeases []string
	// plugins are the manifests of the exec plugins to run; none by default.
	plugins []string
	// backup schedules encrypted backups to an S3-compatible bucket.
	backup    scheduledBackupOptions
	cluster   clusterOptions
	telemetry telemetryOptions
	mqtt      mqttOptions
	// version is the binary's version, which install commands pin agents to.
	version string
	// shellIdle and shellMax limit web terminal sessions.
	shellIdle, shellMax time.Duration

	// apm, on a member of an AP cluster, is the member runHub serves the
	// master layer of (runAPHub): set while it is a master.
	apm *apMember
}

func newHubCmd() *cobra.Command {
	opts := hubOptions{}
	var noLANName bool
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
			"A hub is a cluster of one; --join adds it to the cluster of another hub, with which it\n" +
			"shares its store over --cluster-listen (see docs/cluster.md).\n\n" +
			"--prometheus-url points the hub at an existing Prometheus; device charts then show its\n" +
			"node-exporter data (see docs/prometheus.md).\n\n" +
			"--discover-subnet turns on network discovery: hosts without an agent show up as\n" +
			"unmanaged devices (see docs/discovery.md); CIDR@device sweeps a subnet from that device's\n" +
			"agent instead, within its --allow-scan. --new-device-alerts CHANNEL then sends a\n" +
			"notification for every new host (see docs/discovery.md). --pihole-url and --dhcp-leases add\n" +
			"the hosts a Pi-hole or a DHCP server knows, with their names, on every VLAN (see docs/pihole.md);\n" +
			"--netalertx-url adds the devices a NetAlertX knows (see docs/netalertx.md).\n\n" +
			"--beszel-url reads the systems a Beszel hub monitors, with their status and usage (see docs/beszel.md).\n\n" +
			"--talosconfig reads Talos nodes through the Talos API: versions, services, memory and load (see docs/talos.md).\n\n" +
			"--plugin runs the exec plugin a manifest describes, as a child process of the hub (see docs/plugins.md).\n\n" +
			"--backup-interval uploads an encrypted backup to an S3-compatible bucket at that interval and keeps\n" +
			"the newest --backup-keep, without the CA key unless --backup-include-ca; in a cluster one master does (see docs/backup.md).\n\n" +
			"--mqtt-listen serves an embedded MQTT broker over TLS for the users and devices of --mqtt-clients (see docs/mqtt.md).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.adminPassword = os.Getenv("HEARTH_ADMIN_PASSWORD")
			opts.joinTokenEnv = os.Getenv("HEARTH_JOIN_TOKEN")
			opts.piholePassword = os.Getenv("HEARTH_PIHOLE_PASSWORD")
			opts.netalertxToken = os.Getenv("HEARTH_NETALERTX_TOKEN")
			opts.beszelPassword = os.Getenv("HEARTH_BESZEL_PASSWORD")
			opts.version = cmd.Root().Version
			opts.lanName = !noLANName
			if v := os.Getenv("HEARTH_DISCOVER_INTERVAL"); v != "" && !cmd.Flags().Changed("discover-interval") {
				d, err := time.ParseDuration(v)
				if err != nil {
					return fmt.Errorf("HEARTH_DISCOVER_INTERVAL: %w", err)
				}
				opts.discoverInterval = d
			}
			if err := opts.backup.fromEnv(cmd); err != nil {
				return err
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
			"(default: this hostname, the hub's private LAN IPv4 addresses, localhost, 127.0.0.1, ::1)")
	cmd.Flags().BoolVar(&noLANName, "no-lan-name", false,
		"do not answer at "+discovery.LANName+": no mDNS announcement, and the certificate does not name it")
	cmd.Flags().StringVar(&opts.assetsDir, "assets-dir", "",
		"directory of release archives and checksums.txt to serve at /download/ for `install.sh --from-hub`")
	cmd.Flags().StringVar(&opts.prometheusURL, "prometheus-url", os.Getenv("HEARTH_PROMETHEUS_URL"),
		"Prometheus server to read device charts from, e.g. http://prometheus.lan:9090 (env HEARTH_PROMETHEUS_URL)")
	cmd.Flags().StringVar(&opts.automationsDir, "automations-dir", "",
		"directory of automation YAML files the hub imports into its store once, on its first start (default <data-dir>/automations; see docs/automations.md)")
	cmd.Flags().StringVar(&opts.runbooksDir, "runbooks-dir", "",
		"directory of runbook YAML files the hub imports into its store once, on its first start (default <data-dir>/runbooks; see docs/runbooks.md)")
	cmd.Flags().StringVar(&opts.notifyConfig, "notify-config", os.Getenv("HEARTH_NOTIFY_CONFIG"),
		"file of notification channels (ntfy, Telegram) the hub imports into its store once, on its first start (env HEARTH_NOTIFY_CONFIG; default <data-dir>/notify.yaml if it exists; see docs/notifications.md)")
	cmd.Flags().StringArrayVar(&opts.dangerousAutomations, "allow-dangerous-automation", nil,
		"id of an automation allowed to take dangerous actions, such as exec, without approval; repeatable, "+
			"added to dangerous_automations of the policy; a grant of this host only (default: none)")
	cmd.Flags().BoolVar(&opts.automationsDryRun, "automations-dry-run", false,
		"run automations as dry runs: each action's policy decision is audited, and no action runs")
	cmd.Flags().StringSliceVar(&opts.discoverSubnets, "discover-subnet", splitList(os.Getenv("HEARTH_DISCOVER_SUBNETS")),
		"IPv4 subnet to discover hosts on with an ARP sweep and mDNS, e.g. 192.168.1.0/24, or \"auto\" for the hub's own LANs, "+
			"or CIDR@device to sweep it from that device's agent (within its Network scan capability); "+
			"repeatable (env HEARTH_DISCOVER_SUBNETS, comma-separated; default: off; see docs/discovery.md)")
	cmd.Flags().DurationVar(&opts.discoverInterval, "discover-interval", discovery.DefaultInterval,
		"time between network discovery scans, Pi-hole/DHCP lease/NetAlertX imports and Beszel and Talos reads (env HEARTH_DISCOVER_INTERVAL)")
	cmd.Flags().StringVar(&opts.newDeviceAlerts, "new-device-alerts", os.Getenv("HEARTH_NEW_DEVICE_ALERTS"),
		"notification channel to tell about every new host network discovery finds (env HEARTH_NEW_DEVICE_ALERTS; "+
			"default: off; see docs/discovery.md)")
	cmd.Flags().StringVar(&opts.piholeURL, "pihole-url", os.Getenv("HEARTH_PIHOLE_URL"),
		"Pi-hole v6 to import network clients and DHCP leases from, e.g. http://pi.hole (env HEARTH_PIHOLE_URL; "+
			"password from env HEARTH_PIHOLE_PASSWORD or --pihole-password-file; see docs/pihole.md)")
	cmd.Flags().StringVar(&opts.piholePasswordFile, "pihole-password-file", os.Getenv("HEARTH_PIHOLE_PASSWORD_FILE"),
		"file holding the Pi-hole app password, mode 0600 (env HEARTH_PIHOLE_PASSWORD_FILE)")
	cmd.Flags().StringVar(&opts.netalertxURL, "netalertx-url", os.Getenv("HEARTH_NETALERTX_URL"),
		"NetAlertX API server to import devices from, e.g. http://netalertx.lan:20212 (env HEARTH_NETALERTX_URL; "+
			"API token from env HEARTH_NETALERTX_TOKEN or --netalertx-token-file; see docs/netalertx.md)")
	cmd.Flags().StringVar(&opts.netalertxTokenFile, "netalertx-token-file", os.Getenv("HEARTH_NETALERTX_TOKEN_FILE"),
		"file holding the NetAlertX API token, mode 0600 (env HEARTH_NETALERTX_TOKEN_FILE)")
	cmd.Flags().StringVar(&opts.beszelURL, "beszel-url", os.Getenv("HEARTH_BESZEL_URL"),
		"Beszel hub to read systems from, e.g. http://beszel.lan:8090 (env HEARTH_BESZEL_URL; needs --beszel-email "+
			"and a password from env HEARTH_BESZEL_PASSWORD or --beszel-password-file; see docs/beszel.md)")
	cmd.Flags().StringVar(&opts.beszelEmail, "beszel-email", os.Getenv("HEARTH_BESZEL_EMAIL"),
		"email of the Beszel user the hub logs in as; a read-only user is enough (env HEARTH_BESZEL_EMAIL)")
	cmd.Flags().StringVar(&opts.beszelPasswordFile, "beszel-password-file", os.Getenv("HEARTH_BESZEL_PASSWORD_FILE"),
		"file holding the Beszel user's password, mode 0600 (env HEARTH_BESZEL_PASSWORD_FILE)")
	cmd.Flags().StringVar(&opts.talosconfig, "talosconfig", os.Getenv("HEARTH_TALOSCONFIG"),
		"talosconfig to read Talos nodes with, read-only; an os:reader one is enough (env HEARTH_TALOSCONFIG; see docs/talos.md)")
	cmd.Flags().StringVar(&opts.talosContext, "talos-context", os.Getenv("HEARTH_TALOS_CONTEXT"),
		"context of the talosconfig to use (env HEARTH_TALOS_CONTEXT; default: its current context)")
	cmd.Flags().StringSliceVar(&opts.talosNodes, "talos-nodes", splitList(os.Getenv("HEARTH_TALOS_NODES")),
		"Talos nodes to read, replacing the talosconfig context's nodes (env HEARTH_TALOS_NODES, comma-separated)")
	cmd.Flags().StringArrayVar(&opts.dhcpLeases, "dhcp-leases", splitList(os.Getenv("HEARTH_DHCP_LEASES")),
		"DHCP lease file to import hosts from, dnsmasq (/var/lib/misc/dnsmasq.leases) or ISC dhcpd (dhcpd.leases); "+
			"repeatable (env HEARTH_DHCP_LEASES, comma-separated)")
	cmd.Flags().StringArrayVar(&opts.plugins, "plugin", splitList(os.Getenv("HEARTH_PLUGINS")),
		"manifest of an exec plugin to run on the hub, e.g. /etc/hearth/plugins/lamp/plugin.yaml; repeatable "+
			"(env HEARTH_PLUGINS, comma-separated; default: none; see docs/plugins.md)")
	addBackupFlags(cmd, &opts.backup)
	addTelemetryFlags(cmd, &opts.telemetry)
	addMQTTFlags(cmd, &opts.mqtt)
	cmd.Flags().DurationVar(&opts.shellIdle, "terminal-idle-timeout", hub.DefaultShellIdleTimeout,
		"end a web terminal session after this long without input")
	cmd.Flags().DurationVar(&opts.shellMax, "terminal-max-duration", hub.DefaultShellMaxDuration,
		"end any web terminal session this long after it opened")
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
	if err := backup.PrepareDataDir(opts.dataDir); err != nil {
		return err
	}
	allowedRoles, err := opts.cluster.allowedRoles()
	if err != nil {
		return err
	}
	if err := opts.cluster.check(); err != nil {
		return err
	}
	if opts.apm == nil {
		// A member runs its store and gossip all along, and the master
		// layer below only while it is a master.
		return runClusterHub(ctx, opts, allowedRoles, log)
	}
	telemetryOff, err := opts.telemetry.off()
	if err != nil {
		return err
	}
	var subnets []netip.Prefix
	var autoSubnets bool
	var scanFrom map[string][]netip.Prefix
	if len(opts.discoverSubnets) > 0 {
		var err error
		if subnets, autoSubnets, scanFrom, err = discovery.ParseSubnetsFrom(opts.discoverSubnets); err != nil {
			return fmt.Errorf("--discover-subnet: %w", err)
		}
	}
	importSources, err := leaseSources(opts)
	if err != nil {
		return err
	}
	beszelClient, err := beszelSource(opts)
	if err != nil {
		return err
	}
	talosClient, err := talosSource(opts)
	if err != nil {
		return err
	}
	var manifests []plugins.Manifest
	for _, path := range opts.plugins {
		m, err := plugins.LoadManifest(path)
		if err != nil {
			return fmt.Errorf("--plugin: %w", err)
		}
		manifests = append(manifests, m)
	}
	hosts := hubHosts(ctx, opts.hosts, opts.lanName, log)
	var agentPort string
	if _, port, err := net.SplitHostPort(opts.listen); err == nil && port != "0" {
		agentPort = port
	}
	// Opened and closed by runClusterHub.
	st, ca, node := opts.apm.st, opts.apm.ca, opts.apm.node
	// Host metrics stay in a database of this hub's own, outside the
	// replicated store: they are too many writes to replicate.
	ms, err := metrics.Open(ctx, filepath.Join(opts.dataDir, metricsDBFile), nil, log)
	if err != nil {
		return err
	}
	defer ms.Close()
	serverCert, err := newServerCert(ctx, ca, hosts, node.Epoch(), log)
	if err != nil {
		return err
	}
	sealers, err := newHubSealers(ctx, ca, log)
	if err != nil {
		return err
	}
	node.SetResealer(sealers.reseal)

	// The configuration is set below, before anything decides: from the
	// store's documents, or from the files until the store holds any.
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), policy.Config{})
	notifier := &notify.Notifier{}
	automationsDir := opts.automationsDir
	if automationsDir == "" {
		automationsDir = filepath.Join(opts.dataDir, "automations")
	}
	hubID := node.ID()
	configWatcher := hubconfig.NewWatcher(hubconfig.WatcherConfig{
		Store: st.ConfigDocs(), Sealer: sealers.notify, Policy: pol, Notifier: notifier,
		HostDangerous: opts.dangerousAutomations, Actor: hubID, Log: log.With("component", "config"),
		Files: hubconfig.Files{
			Policy: filepath.Join(opts.dataDir, policy.ConfigFile), Notify: notifyConfigPath(opts),
			AutomationsDir: automationsDir, RunbooksDir: runbooksDirOf(opts),
		},
	})
	configDocs, err := applyHubConfig(ctx, opts, st, configWatcher, pol, notifier, log)
	if err != nil {
		return err
	}
	// An outcome a cluster without quorum cannot take waits here for it.
	spool, err := policy.OpenSpool(filepath.Join(opts.dataDir, auditSpoolDir), st.Audit(), log.With("component", "audit-spool"))
	if err != nil {
		return err
	}
	pol.SpoolTo(spool)
	var beszelReader *beszel.Reader
	if beszelClient != nil {
		beszelReader = beszel.NewReader(beszel.ReaderConfig{
			Client: beszelClient, Interval: opts.discoverInterval, Policy: pol, Log: log.With("component", "beszel"),
		})
	}
	var talosReader *talos.Reader
	if talosClient != nil {
		talosReader = talos.NewReader(talos.ReaderConfig{
			Client: talosClient, Interval: opts.discoverInterval, Policy: pol, Log: log.With("component", "talos"),
		})
	}
	reg := hub.NewRegistry(hub.RegistryConfig{Store: st, Log: log})
	// Devices whose agents stream to another master change here by
	// merges: the UI follows them, the automations do not (#266).
	st.ObserveMerges(reg.Merged)
	defer st.ObserveMerges(nil)
	agents := hub.NewAgents(st.Devices())
	kube, err := newKubeManager(st, sealers.kube, pol, log)
	if err != nil {
		return err
	}
	var pluginMgr *plugins.Manager
	if len(manifests) > 0 {
		if pluginMgr, err = plugins.New(plugins.Config{
			Manifests: manifests, Policy: pol, Log: log.With("component", "plugins"),
		}); err != nil {
			return fmt.Errorf("--plugin: %w", err)
		}
	}
	pve, err := newProxmoxManager(st, sealers.proxmox, pol, log)
	if err != nil {
		return err
	}
	esp := esphome.NewManager(esphome.Config{Store: st, Sealer: sealers.esphome, Policy: pol, Log: log})
	owrt := openwrt.NewManager(openwrt.Config{Store: st, Sealer: sealers.openwrt, Policy: pol, Log: log})
	// The routers' clients feed network discovery; the importer leaves them
	// out while no router is read.
	importSources = append(importSources, owrt)
	// So do the OPNsense firewalls' leases and ARP tables.
	opn := opnsense.NewManager(opnsense.Config{Store: st, Sealer: sealers.opnsense, Policy: pol, Log: log})
	importSources = append(importSources, opn)
	// So do the UniFi controllers' clients.
	ufi := unifi.NewManager(unifi.Config{Store: st, Sealer: sealers.unifi, Policy: pol, Log: log})
	importSources = append(importSources, ufi)
	if opts.newDeviceAlerts != "" && !notifier.Has(opts.newDeviceAlerts) {
		return fmt.Errorf("--new-device-alerts: no notification channel %q (see --notify-config)", opts.newDeviceAlerts)
	}
	// A member's database holds only its shards: its backups copy the
	// whole cluster store.
	snapshot := node.Snapshot
	clustered := func() bool { return !node.Status().Alone() }
	backups, err := backupScheduler(opts, st, pol, notifier, clustered, snapshot,
		log.With("component", "backup"))
	if err != nil {
		return err
	}
	notifyApprovals(pol, st, notifier, hosts[0], agentPort, log)
	// stopping ends agent streams and /events subscriptions as soon as either
	// server begins shutting down, so Shutdown waits only on ordinary requests
	// and agents see a clean end of stream and reconnect at once.
	stopping, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	var runbookDocs automation.DocSource
	if configDocs {
		runbookDocs = hubconfig.StoreDocs(st.ConfigDocs(), store.ConfigRunbook, runbooksDirOf(opts), "", time.Now)
	}
	// owns says which items (automations, runbook runs,
	// approvals) this master runs: those it owns on the ring of masters.
	owns := node.Masters().Owns
	pol.SweepOnly(owns)
	// A master cut off from every other member fails closed.
	pol.FailClosedWhen(node.Isolated)
	runbooks, err := newRunbooks(opts, st, sealers.runbook, pol, agents, notifier, kube, pluginMgr, talosClient, runbookDocs, owns, log)
	if err != nil {
		return err
	}
	// The scanner scans when an admin asks (POST /api/v1/network/scan) on
	// any hub, and on its schedule only with --discover-subnet.
	scanner := discovery.New(discovery.Config{
		Subnets: subnets, Auto: autoSubnets, From: scanFrom, Agents: agents, Interval: opts.discoverInterval,
		Hosts: st.NetworkHosts(), Policy: pol, Events: reg, Log: log.With("component", "discovery"),
	})
	scheduledScans := len(subnets) > 0 || autoSubnets || len(scanFrom) > 0
	networkScans := hub.NewNetworkScans(scanner, reg, log.With("component", "discovery"))
	// Without a schedule, presence follows discovery's default interval.
	var discoverInterval time.Duration
	if scheduledScans {
		discoverInterval = opts.discoverInterval
	}
	cfg := hub.Config{
		DiscoverInterval:  discoverInterval,
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
		Beszel:            beszelSnapshotter(beszelReader),
		Talos:             talosSnapshotter(talosReader),
		Metrics:           ms,
		NetEdges:          hub.NewNetEdges(),
		Agents:            agents,
		Kube:              kube,
		Proxmox:           pve,
		ESPHome:           esp,
		OpenWrt:           owrt,
		OPNsense:          opn,
		UniFi:             ufi,
		Plugins:           pluginMgr,
		Notify:            notifier,
		NetworkScans:      networkScans,
		Version:           opts.version,
		Runbooks:          runbooks,
		TelemetryOff:      telemetryOff,
		ShellIdleTimeout:  opts.shellIdle,
		ShellMaxDuration:  opts.shellMax,
	}
	if exe, err := os.Executable(); err == nil {
		cfg.VerifyPassword = hub.ChildVerifier(exe)
	} else {
		log.WarnContext(ctx, "cannot find own binary: verifying login passwords in-process", "err", err)
	}
	// ready is closed once the hub has caught up with the cluster.
	ready := opts.apm.ready
	// Requests wait for the first sync with the cluster. Every master
	// takes agent streams; calls for a stream on another master are
	// forwarded to it.
	cfg.Ready = ready
	cfg.Leadership = node
	cfg.ConfigDrift = func(context.Context) (any, error) { return node.Status().HostFlagDrift(), nil }
	cfg.Masters = node
	cfg.ClusterAdmin = apClusterAdmin{node}
	cfg.ClusterCA = apClusterCA{node}
	if _, port, err := net.SplitHostPort(opts.httpListen); err == nil && port != "0" {
		cfg.HTTPPort = port
	}
	kinds := automation.Builtin(log)
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{
		Devices: hub.AutomationDevices(reg),
		Network: hub.AutomationNetwork(reg),
		Metrics: hub.AutomationMetrics(st, prom, ms, agents),
		Probers: agents,
		Policy:  pol,
		Log:     log,
	}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{
		Agents: agents, Notifier: notifier, Kube: kube, Plugins: pluginMgr, Probers: agents,
	}))
	kinds.Actions["script"] = automation.Script(automation.ScriptDeps{Devices: st.Devices()})
	cfg.AutomationsDir, cfg.AutomationKinds = automationsDir, kinds
	var automationDocs automation.DocStore
	if configDocs {
		// Saved by the web editor or MCP: automation.apply, audited.
		automationDocs = hubconfig.StoreDocs(st.ConfigDocs(), store.ConfigAutomation, automationsDir,
			string(policy.AutomationApply), time.Now)
		cfg.AutomationDocs = automationDocs
		// The web UI's editors validate and seal as `hearth config import`.
		cfg.ConfigSealer, cfg.ConfigKinds = sealers.notify, cliKinds
	}
	// A backup from the web UI is the one `hearth backup` writes.
	cfg.Backup, cfg.BackupDir = webBackup(opts, st, clustered, snapshot), opts.dataDir
	// Exec plugins for devices keep their programs in the data dir.
	cfg.PluginBlobs = hub.NewPluginBlobs(opts.dataDir)
	// The web editor and MCP write the same directory under one lock.
	var automationsMu sync.Mutex
	cfg.AutomationsLock = &automationsMu
	errLog := slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	// A request that demotes this master ends the master layer: it still
	// answers, and audits its outcome.
	baseCtx := func(net.Listener) context.Context { return opts.apm.ctx }
	// The UI and API, served on both listeners. Over TLS they share the agent
	// port, so browsers get HTTPS with the hub CA (see docs/https.md).
	dashboardAudit := hub.NewDashboardAudit(pol, log)
	cfg.DashboardAudit = dashboardAudit
	webH := hub.NewHTTPHandler(cfg)
	uiMux := http.NewServeMux()
	uiMux.Handle("/", webH)
	uiMux.Handle("GET /api/v1/events", hub.EndOnStop(stopping, webH))
	uiMux.Handle("GET /api/v1/devices/{id}/logs", hub.EndOnStop(stopping, webH))
	uiMux.Handle("GET /api/v1/devices/{id}/shell", hub.EndOnStop(stopping, webH))
	// Other masters forward calls for the agents streaming here, and
	// proxy the log streams and terminals of their devices.
	mm := http.NewServeMux()
	mm.Handle("/agents/", hub.AgentsHandler(agents, ms, log))
	mm.Handle("/api/", hub.ProxiedHandler(uiMux))
	node.SetMasterHandler(mm)
	defer node.SetMasterHandler(nil)
	uiMux.Handle("GET /api/v1/guest/{token}/events", hub.EndOnStop(stopping, webH))
	var mcpPlugins mcpserver.Plugins
	if pluginMgr != nil {
		mcpPlugins = pluginMgr
	}
	uiMux.Handle(mcpserver.Path, hub.EndOnStop(stopping, mcpserver.Handler(mcpserver.Config{
		Devices: st.Devices(), Tokens: st.MCPTokens(), Policy: pol, Agents: agents, Kube: kube, Plugins: mcpPlugins,
		DevicePlugins: hub.DevicePluginRunner{Agents: agents, Store: st, Policy: pol},
		Metrics: hub.AutomationMetrics(st, prom, ms, agents), AutomationsDir: automationsDir, AutomationDocs: automationDocs, AutomationKinds: kinds, AutomationsLock: &automationsMu,
		Version: opts.version, Log: log,
	})))
	tlsCfg := hub.TLSConfigFunc(ca, serverCert.Load)
	// Joining hubs call ClusterService.Join over TLS.
	tlsWeb := http.NewServeMux()
	tlsWeb.Handle("/", uiMux)
	tlsWeb.Handle(cluster.NewAPJoinServer(node, st, ca, pol, log).Handler())
	agentSrv := &http.Server{
		Handler:           hub.NewTLSHandler(cfg, tlsWeb),
		TLSConfig:         tlsCfg,
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
	hub.RegisterCARouteFunc(webMux, ca.Cert)
	// No WriteTimeout: /api/v1/events is a long-lived stream.
	webSrv := &http.Server{
		Handler:           webMux,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          errLog,
		BaseContext:       baseCtx,
	}
	webSrv.RegisterOnShutdown(stop)
	lc := &net.ListenConfig{}
	agentLn, webLn := opts.agentLn, opts.webLn
	if agentLn == nil {
		if agentLn, err = lc.Listen(ctx, "tcp", opts.listen); err != nil {
			return fmt.Errorf("listen on %s: %w", opts.listen, err)
		}
	}
	if webLn == nil {
		if webLn, err = lc.Listen(ctx, "tcp", opts.httpListen); err != nil {
			_ = agentLn.Close()
			return fmt.Errorf("listen on %s: %w", opts.httpListen, err)
		}
	}
	fp := ca.Fingerprint()
	logAttrs := []any{
		"addr", agentLn.Addr().String(), "http_addr", webLn.Addr().String(),
		"hosts", hosts, "data_dir", opts.dataDir, "ca_fingerprint", hex.EncodeToString(fp[:]),
	}
	logAttrs = append(logAttrs, "node_id", node.ID())
	logAttrs = append(logAttrs, "prometheus", prom != nil, "pihole", opts.piholeURL != "", "netalertx", opts.netalertxURL != "",
		"beszel", opts.beszelURL != "", "talos", opts.talosconfig != "", "dhcp_lease_files", len(opts.dhcpLeases),
		"plugins", len(manifests))
	log.InfoContext(ctx, "hub listening", logAttrs...)

	var builtin []*automation.Automation
	if opts.newDeviceAlerts != "" {
		a, err := automation.NewDeviceAlerts(opts.newDeviceAlerts, kinds)
		if err != nil {
			return fmt.Errorf("--new-device-alerts: %w", err)
		}
		builtin = append(builtin, a)
		if len(subnets) == 0 && !autoSubnets && len(scanFrom) == 0 {
			log.WarnContext(ctx, "new-device alerts are on but network discovery is off: set --discover-subnet")
		}
	}
	var automationSource automation.DocSource
	if configDocs {
		automationSource = configWatcher.Automations()
	}
	var ringChanged <-chan struct{}
	c, unsubscribe := node.Masters().Subscribe()
	defer unsubscribe()
	ringChanged = c
	automations := automation.New(automation.Config{
		Dir:     automationsDir,
		Source:  automationSource,
		Builtin: builtin,
		Kinds:   kinds,
		Policy:  pol,
		Runs:    st.AutomationRuns(),
		Log:     log,
		DryRun:  opts.automationsDryRun,
		Owns:    owns,
		Owned:   ringChanged,
	})
	// Local automations run on their devices: their agents get them (#70).
	agents.SetLocalRules(hub.LocalRulesConfig{
		Automations: automations, Docs: st.ConfigDocs(), Policy: pol, Audit: st.Audit(),
		Runs: st.AutomationRuns(), Devices: st.Devices(),
	})

	var importer *discovery.Importer
	if len(importSources) > 0 {
		importer = discovery.NewImporter(discovery.ImportConfig{
			Sources: importSources, Interval: opts.discoverInterval,
			Hosts: st.NetworkHosts(), Policy: pol, Log: log.With("component", "network-import"),
		})
	}

	// Bound last, after every early return, so Run always closes it.
	broker, err := newMQTTBroker(ctx, opts, ca, serverCert.Load, st, log)
	if err != nil {
		_ = agentLn.Close()
		_ = webLn.Close()
		return err
	}
	g, gctx := errgroup.WithContext(ctx)
	runAPLoops(gctx, g, node, apLoops{
		agents: agents, reg: reg, st: st, pol: pol, automations: automations, runbooks: runbooks,
		scanner: scanner, scheduledScans: scheduledScans, importer: importer, beszel: beszelReader, talos: talosReader, backups: backups,
		ready: ready, log: log, lanName: opts.lanName,
	})
	// Every master runs the scans asked for of it.
	g.Go(func() error { return networkScans.Run(gctx) })
	// Every hub of a cluster watches the Kubernetes clusters itself.
	g.Go(func() error { return kube.Run(gctx) })
	// And reads the Proxmox servers itself.
	g.Go(func() error { return pve.Run(gctx) })
	// And keeps a connection to every ESPHome device itself.
	g.Go(func() error { return esp.Run(gctx) })
	// And reads the OpenWrt routers itself.
	g.Go(func() error { return owrt.Run(gctx) })
	// And the OPNsense firewalls.
	g.Go(func() error { return opn.Run(gctx) })
	// And the UniFi controllers.
	g.Go(func() error { return ufi.Run(gctx) })
	// And runs the exec plugins itself, if any: commands may reach any hub.
	if pluginMgr != nil {
		g.Go(func() error { return pluginMgr.Run(gctx) })
	}
	// Every hub applies the configuration documents, whichever hub wrote
	// them; a cluster member imports its files once it has caught up.
	if configDocs {
		g.Go(func() error { return configWatcher.Run(gctx) })
		// A member imports once it has found the cluster and copied
		// its rows: before, it would see no documents of the cluster's,
		// and import its files over them, alone on a ring of itself.
		g.Go(func() error {
			select {
			case <-gctx.Done():
				return nil
			case <-ready:
			}
			if !opts.apm.caughtUp.Load() {
				log.WarnContext(gctx, "configuration files not imported: this member has not caught up with the "+
					"cluster; import them with `hearth config import` if the cluster holds none")
				return nil
			}
			if err := configWatcher.ImportFirst(gctx); err != nil {
				log.ErrorContext(gctx, "configuration files not imported", "err", err)
			}
			return nil
		})
	}
	// Every hub prunes its own metrics.
	g.Go(func() error { return ms.Run(gctx) })
	g.Go(func() error { return dashboardAudit.Run(gctx) })
	// Every hub checks the telemetry answer; one master sends.
	telemetryLeader := node.Masters().Singleton("loop/telemetry", ready)
	telemetrySender := newTelemetrySender(opts, telemetryOff, st, telemetryLeader, log.With("component", "telemetry"))
	g.Go(func() error { return telemetrySender.Run(gctx) })
	// Every hub writes the audit entries it spooled.
	g.Go(func() error { return spool.Run(gctx) })
	g.Go(func() error { return serve(gctx, agentSrv, func() error { return agentSrv.ServeTLS(agentLn, "", "") }) })
	g.Go(func() error { return serve(gctx, webSrv, func() error { return webSrv.Serve(webLn) }) })
	// Every hub with --mqtt-listen runs a broker of its own.
	if broker != nil {
		g.Go(func() error { return broker.Run(gctx) })
	}
	// The CLI's promote, demote and remove, decided here.
	node.SetRoleChanges(apRoleChanges(pol, apClusterAdmin{node}))
	defer node.SetRoleChanges(nil)
	// And its hub CA rotation steps.
	node.SetCAPolicy(pol)
	defer node.SetCAPolicy(nil)
	err = g.Wait()
	log.InfoContext(ctx, "hub stopped")
	return err
}

// newKubeManager returns the manager of adopted Kubernetes clusters. Their
// kubeconfigs are sealed with sealer (hubSealers).
func newKubeManager(st *store.Store, sealer *kubernetes.Sealer, pol *policy.Engine, log *slog.Logger) (*kubernetes.Manager, error) {
	return kubernetes.NewManager(kubernetes.Config{Store: st, Sealer: sealer, Policy: pol, Log: log}), nil
}

// newProxmoxManager returns the manager of adopted Proxmox VE servers. Their
// API tokens are sealed with sealer (hubSealers).
func newProxmoxManager(st *store.Store, sealer *kubernetes.Sealer, pol *policy.Engine, log *slog.Logger) (*proxmox.Manager, error) {
	return proxmox.NewManager(proxmox.Config{Store: st, Sealer: sealer, Policy: pol, Log: log}), nil
}

// newRunbooks returns the runbook engine. A run keeps a copy of its runbook
// file, sealed with sealer (hubSealers).
func newRunbooks(opts hubOptions, st *store.Store, sealer *kubernetes.Sealer, pol *policy.Engine, agents *hub.Agents,
	notifier *notify.Notifier, kube *kubernetes.Manager, pluginMgr *plugins.Manager,
	talosClient *talos.Client, docs automation.DocSource, owns func(string) bool, log *slog.Logger,
) (*automation.Runbooks, error) {
	kinds := automation.Builtin(log)
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{
		Agents: agents, Notifier: notifier, Kube: kube, Plugins: pluginMgr, Probers: agents,
	}))
	return automation.NewRunbooks(automation.RunbooksConfig{
		Dir: runbooksDirOf(opts), Source: docs, Kinds: kinds, Policy: pol, Runs: st.RunbookRuns(), Sealer: sealer, Probers: agents,
		KubeNodes: kube, TalosNodes: talosNodes(talosClient), Log: log.With("component", "runbooks"),
		DryRun: opts.automationsDryRun, Owns: owns,
	}), nil
}

// talosNodes returns c as an automation.TalosNodes, nil if c is: a nil
// *talos.Client in the interface would not be nil.
func talosNodes(c *talos.Client) automation.TalosNodes {
	if c == nil {
		return nil
	}
	return c
}

// runbooksDirOf is the directory the hub loads runbooks from.
func runbooksDirOf(opts hubOptions) string {
	if opts.runbooksDir != "" {
		return opts.runbooksDir
	}
	return filepath.Join(opts.dataDir, "runbooks")
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

// notifyApprovals sends every action pol holds to the policy's
// approval_notify channel, with an approval link based at its url or, by
// default, the hub's HTTPS address for host. It reads the policy in effect
// at each hold, so a new policy document applies at once.
func notifyApprovals(pol *policy.Engine, st *store.Store, n *notify.Notifier, host, port string, log *slog.Logger) {
	if port == "" {
		port = defaultPort
	}
	defaultBase := "https://" + net.JoinHostPort(host, port)
	pol.OnHeld(func(ctx context.Context, ap store.Approval) {
		cfg := pol.Config().ApprovalNotify
		if cfg.Channel == "" {
			return
		}
		base := cfg.URL
		if base == "" {
			base = defaultBase
		}
		hub.NewApprovalNotifier(hub.ApprovalNotifierConfig{
			Links: st.ApprovalLinks(), Notifier: n, Channel: cfg.Channel, BaseURL: base, Log: log,
		})(ctx, ap)
	})
}

// applyHubConfig puts the hub's configuration in effect before anything
// decides, and reports whether the store's documents are its source (schema
// 28 or newer). A master imports its files into an empty store once it has
// caught up with the cluster. Until the store holds documents, the files are
// in effect, as they always were.
func applyHubConfig(ctx context.Context, opts hubOptions, st *store.Store, w *hubconfig.Watcher,
	pol *policy.Engine, notifier *notify.Notifier, log *slog.Logger,
) (bool, error) {
	docs, err := st.ConfigDocs().Available(ctx)
	if err != nil {
		return false, err
	}
	applied := false
	if docs {
		if applied, err = w.Sync(ctx); err != nil {
			return false, err
		}
	} else {
		log.WarnContext(ctx, "the database predates configuration documents: this hub reads its configuration files "+
			"until every hub of the cluster is upgraded and it restarts", "schema_needed", store.ConfigDocsSchema)
	}
	if applied {
		return docs, nil
	}
	polCfg, err := loadPolicyConfig(opts.dataDir)
	if err != nil {
		return false, err
	}
	polCfg.DangerousAutomations = append(polCfg.DangerousAutomations, opts.dangerousAutomations...)
	n, err := loadNotifier(opts, log)
	if err != nil {
		return false, err
	}
	if ch := polCfg.ApprovalNotify.Channel; ch != "" && !n.Has(ch) {
		return false, fmt.Errorf("policy config: approval_notify.channel %q is not in the notification channels file", ch)
	}
	pol.SetConfig(polCfg)
	notifier.Replace(n)
	return docs, nil
}

// loadNotifier reads the notification channels file: --notify-config, or
// <data-dir>/notify.yaml if it exists. Without one the hub has no channels.
// It logs channel names only, never their addresses or credentials.

// notifyConfigPath is the notification channels file the hub reads.
func notifyConfigPath(opts hubOptions) string {
	if opts.notifyConfig != "" {
		return opts.notifyConfig
	}
	return filepath.Join(opts.dataDir, "notify.yaml")
}

func loadNotifier(opts hubOptions, log *slog.Logger) (*notify.Notifier, error) {
	path := notifyConfigPath(opts)
	if opts.notifyConfig == "" {
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

// hubHosts are the names of the hub certificate: the --host values when
// given, as given; else defaultHubHosts with the hub's LAN addresses now,
// so a restart after an address change (DHCP) issues a certificate for the
// new ones. With lanName, discovery.LANName comes last: never the
// preferred name, which install commands and agents use.
func hubHosts(ctx context.Context, flagHosts []string, lanName bool, log *slog.Logger) []string {
	hosts := flagHosts
	if len(hosts) == 0 {
		lan, err := discovery.LANAddrs()
		if err != nil {
			log.WarnContext(ctx, "list the LAN addresses for the hub certificate", "err", err)
		}
		hosts = defaultHubHosts(hostnameOr("localhost"), lan)
	}
	if lanName && !slices.ContainsFunc(hosts, func(h string) bool { return strings.EqualFold(h, discovery.LANName) }) {
		hosts = append(slices.Clone(hosts), discovery.LANName)
	}
	return hosts
}

// defaultHubHosts are the hub certificate's names without --host: the
// hostname, the LAN addresses lan and the loopback names. The first name
// that is not loopback is the one install commands and notification links
// name, so a hostname other devices are unlikely to resolve (a single label
// or a .local name: hub.BareHostname) goes after the LAN addresses.
func defaultHubHosts(hostname string, lan []netip.Addr) []string {
	var hosts []string
	if !hub.BareHostname(hostname) {
		hosts = append(hosts, hostname)
	}
	for _, a := range lan {
		hosts = append(hosts, a.String())
	}
	if hub.BareHostname(hostname) {
		hosts = append(hosts, hostname)
	}
	return append(hosts, "localhost", "127.0.0.1", "::1")
}
