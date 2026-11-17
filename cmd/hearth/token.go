// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

type tokenCreateOptions struct {
	dataDir string
	ttl     time.Duration
	labels  map[string]string
	hubURL  string
}

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage enrollment tokens"}
	cmd.AddCommand(newTokenCreateCmd())
	return cmd
}

func newTokenCreateCmd() *cobra.Command {
	opts := tokenCreateOptions{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a single-use enrollment token",
		Long: "Create a single-use enrollment token and print it with the command that joins a device.\n" +
			"Run it on the hub host: it reads the hub's data dir directly.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTokenCreate(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().DurationVar(&opts.ttl, "ttl", 15*time.Minute, "how long the token stays valid")
	cmd.Flags().StringToStringVar(&opts.labels, "labels", nil, "labels for the enrolled device, k=v[,k=v]")
	cmd.Flags().StringVar(&opts.hubURL, "hub-url", "https://"+hostnameOr("localhost")+":"+defaultPort,
		"hub URL to put in the join command")
	return cmd
}

func runTokenCreate(ctx context.Context, opts tokenCreateOptions, out io.Writer) error {
	if opts.ttl <= 0 {
		return errors.New("--ttl must be positive")
	}
	// Read the CA before opening the store, so a wrong data dir fails without
	// creating an empty database there.
	caCert, err := pki.LoadCACert(opts.dataDir)
	if err != nil {
		return fmt.Errorf("%w (has `hearth hub` been started with --data-dir %s?)", err, opts.dataDir)
	}
	st, err := store.Open(ctx, filepath.Join(opts.dataDir, dbFile))
	if err != nil {
		return err
	}
	defer st.Close()

	tok, err := pki.NewToken(caCert)
	if err != nil {
		return err
	}
	expires := time.Now().Add(opts.ttl)
	err = policy.New(st.Audit()).Do(ctx, policy.Request{
		ActorKind: policy.ActorAdmin,
		ActorID:   adminActor(),
		Action:    policy.TokenCreate,
		Detail:    map[string]any{"ttl": opts.ttl.String(), "labels": opts.labels},
	}, func(ctx context.Context) error {
		return st.Tokens().Create(ctx, tok.Secret, opts.labels, expires)
	})
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Enrollment token (single use, expires %s):\n  %s\n\nJoin a device:\n  HEARTH_TOKEN=%s hearth agent join %s\n",
		expires.Format(time.RFC3339), tok.Encode(), tok.Encode(), opts.hubURL)
	if err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	return nil
}
