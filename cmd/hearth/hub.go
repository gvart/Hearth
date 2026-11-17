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

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

type hubOptions struct {
	dataDir string
	listen  string
	hosts   []string
}

func newHubCmd() *cobra.Command {
	opts := hubOptions{}
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Run the Hearth hub",
		Long: "Run the Hearth hub. On first start it creates its certificate authority and database\n" +
			"in the data dir. Agents enroll and connect over TLS on the listen address.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHub(cmd.Context(), opts, newLogger(cmd.ErrOrStderr()))
		},
	}
	cmd.Flags().StringVar(&opts.dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&opts.listen, "listen", ":"+defaultPort, "address to serve agents on")
	cmd.Flags().StringSliceVar(&opts.hosts, "host", nil,
		"DNS name or IP agents use to reach the hub; repeatable (default: this hostname, localhost, 127.0.0.1, ::1)")
	return cmd
}

func runHub(ctx context.Context, opts hubOptions, log *slog.Logger) error {
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

	srv := &http.Server{
		Handler: hub.NewHandler(hub.Config{
			Store:             st,
			CA:                ca,
			Policy:            policy.New(st.Audit()),
			Log:               log,
			HeartbeatInterval: hub.DefaultHeartbeatInterval,
		}),
		TLSConfig:         hub.TLSConfig(ca, serverCert),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", opts.listen, err)
	}
	fp := ca.Fingerprint()
	log.InfoContext(ctx, "hub listening", "addr", ln.Addr().String(), "hosts", hosts,
		"data_dir", opts.dataDir, "ca_fingerprint", hex.EncodeToString(fp[:]))

	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	log.InfoContext(ctx, "hub shutting down")
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
