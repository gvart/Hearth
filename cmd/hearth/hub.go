// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/hub"
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
	// adminPassword is HEARTH_ADMIN_PASSWORD: it sets the admin password on a
	// hub that has none yet.
	adminPassword string
}

func newHubCmd() *cobra.Command {
	opts := hubOptions{}
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Run the Hearth hub",
		Long: "Run the Hearth hub. On first start it creates its certificate authority and database\n" +
			"in the data dir. Agents enroll and connect over TLS on the listen address; the web UI\n" +
			"and JSON API are served over plain HTTP on the http-listen address.\n\n" +
			"If HEARTH_ADMIN_PASSWORD is set and no admin password is stored yet, it becomes the\n" +
			"admin password. Otherwise use `hearth admin set-password`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.adminPassword = os.Getenv("HEARTH_ADMIN_PASSWORD")
			return runHub(cmd.Context(), opts, newLogger(cmd.ErrOrStderr()))
		},
	}
	cmd.Flags().StringVar(&opts.dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&opts.listen, "listen", ":"+defaultPort, "address to serve agents on (TLS)")
	cmd.Flags().StringVar(&opts.httpListen, "http-listen", ":"+defaultHTTPPort, "address to serve the web UI and API on (plain HTTP)")
	cmd.Flags().StringSliceVar(&opts.hosts, "host", nil,
		"DNS name or IP agents use to reach the hub; repeatable (default: this hostname, localhost, 127.0.0.1, ::1)")
	cmd.Flags().StringVar(&opts.assetsDir, "assets-dir", "",
		"directory of release archives and checksums.txt to serve at /download/ for `install.sh --from-hub`")
	return cmd
}

func runHub(ctx context.Context, opts hubOptions, log *slog.Logger) error {
	if opts.assetsDir != "" {
		if info, err := os.Stat(opts.assetsDir); err != nil || !info.IsDir() {
			return fmt.Errorf("--assets-dir %s is not a directory", opts.assetsDir)
		}
	}
	if err := os.MkdirAll(opts.dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(ctx, filepath.Join(opts.dataDir, dbFile))
	if err != nil {
		return err
	}
	defer st.Close()

	now := time.Now()
	ca, err := pki.LoadOrCreateCA(opts.dataDir, now)
	if err != nil {
		return err
	}
	hosts := opts.hosts
	if len(hosts) == 0 {
		hosts = []string{hostnameOr("localhost"), "localhost", "127.0.0.1", "::1"}
	}
	serverCert, err := ca.IssueServerCert(hosts, now)
	if err != nil {
		return err
	}

	pol := policy.New(st.Audit())
	if err := ensureAdminPassword(ctx, st, pol, opts, log); err != nil {
		return err
	}
	reg := hub.NewRegistry(hub.RegistryConfig{Store: st, Log: log})
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
		Stopping:          stopping,
	}
	if _, port, err := net.SplitHostPort(opts.listen); err == nil && port != "0" {
		cfg.AgentPort = port
	}
	errLog := slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	baseCtx := func(net.Listener) context.Context { return ctx }
	agentSrv := &http.Server{
		Handler:           hub.NewHandler(cfg),
		TLSConfig:         hub.TLSConfig(ca, serverCert),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          errLog,
		BaseContext:       baseCtx,
	}
	agentSrv.RegisterOnShutdown(stop)
	webMux := http.NewServeMux()
	webH := hub.NewHTTPHandler(cfg)
	webMux.Handle("/", webH)
	webMux.Handle("GET /api/v1/events", hub.EndOnStop(stopping, webH))
	hub.RegisterInstallRoutes(webMux, opts.assetsDir)
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
	log.InfoContext(ctx, "hub listening", "addr", agentLn.Addr().String(), "http_addr", webLn.Addr().String(),
		"hosts", hosts, "data_dir", opts.dataDir, "ca_fingerprint", hex.EncodeToString(fp[:]))

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return reg.Run(gctx) })
	g.Go(func() error { return serve(gctx, agentSrv, func() error { return agentSrv.ServeTLS(agentLn, "", "") }) })
	g.Go(func() error { return serve(gctx, webSrv, func() error { return webSrv.Serve(webLn) }) })
	err = g.Wait()
	log.InfoContext(ctx, "hub stopped")
	return err
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
