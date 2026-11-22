// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

type tokenCreateOptions struct {
	dataDir string
	ttl     time.Duration
	labels  map[string]string
	name    string
	hubURL  string
	// hub lets a capable device that enrolls with the token become a hub
	// (#328): a cluster.token.create decision of its own.
	hub    bool
	dryRun bool
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
	cmd.Flags().StringVar(&opts.name, "name", "", "name for the enrolled device (default: its hostname)")
	cmd.Flags().StringVar(&opts.hubURL, "hub-url", "https://"+hostnameOr("localhost")+":"+defaultPort,
		"agent URL of the hub, which the token names; agents enroll there")
	cmd.Flags().BoolVar(&opts.hub, "hub", false,
		"let a capable Linux device installed with the token become a hub: it stores a copy of the data and, "+
			"while the cluster has fewer than 3 masters, becomes a master and holds the CA key")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "decide and audit the action without creating a token")
	return cmd
}

func runTokenCreate(ctx context.Context, opts tokenCreateOptions, out io.Writer) error {
	if opts.ttl <= 0 {
		return errors.New("--ttl must be positive")
	}
	name, err := hub.DeviceName(opts.name)
	if err != nil {
		return fmt.Errorf("--name: %w", err)
	}
	// Read the CA before opening the store, so a wrong data dir fails without
	// creating an empty database there.
	caCert, err := pki.LoadCACert(opts.dataDir)
	if err != nil {
		return fmt.Errorf("%w (has `hearth hub` been started with --data-dir %s?)", err, opts.dataDir)
	}
	st, err := openHubStore(ctx, opts.dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	tok, err := pki.NewToken(caCert)
	if err != nil {
		return err
	}
	expires := time.Now().Add(opts.ttl)
	hubRoles := ""
	detail := hub.TokenDetail(opts.ttl, opts.labels, name)
	if opts.hub {
		hubRoles = cluster.HubRoles.String()
		detail["hub"] = true
	}
	create := func(ctx context.Context) error {
		return st.Tokens().CreateHub(ctx, tok.Secret, name, hubRoles, opts.labels, expires)
	}
	// A hub-eligible token hands the CA key to a master-to-be: decided as a
	// cluster join token is, nested in token.create.
	hubReq := policy.Request{Action: policy.ClusterTokenCreate, Detail: hub.ClusterTokenDetail(opts.ttl, tok.Secret)}
	if opts.hub {
		plain := create
		create = func(ctx context.Context) error {
			_, err := adminDo(ctx, opts.dataDir, st, out, false, hubReq, plain)
			return err
		}
	}
	done, err := adminDo(ctx, opts.dataDir, st, out, opts.dryRun, policy.Request{
		Action: policy.TokenCreate,
		Detail: detail,
	}, create)
	if err == nil && opts.dryRun && opts.hub {
		_, err = adminDo(ctx, opts.dataDir, st, out, true, hubReq, nil)
	}
	if err != nil || !done {
		return err
	}

	// The token is this master's: it says where to enroll.
	enc := tok.EncodeHub(opts.hubURL)
	_, err = fmt.Fprintf(out, "Enrollment token (single use, expires %s):\n  %s\n\nJoin a device:\n  HEARTH_TOKEN=%s hearth agent join\n",
		expires.Format(time.RFC3339), enc, enc)
	if err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	return nil
}
