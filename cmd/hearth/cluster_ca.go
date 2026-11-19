// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/policy"
)

func newClusterCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Rotate the cluster's hub CA",
		Long: "Replace the hub CA of a cluster, in two steps: `rotate` makes a new CA that every hub trusts next to\n" +
			"the old one and renews hubs and agents with it; `finish` makes every hub serve the new CA, re-seals\n" +
			"the stored secrets with its key and drops the old CA and its key. See \"Rotating the hub CA\" in\n" +
			"docs/cluster.md.",
	}
	cmd.AddCommand(newClusterCARotateCmd(), newClusterCAFinishCmd(), newClusterCAStatusCmd())
	return cmd
}

func newClusterCARotateCmd() *cobra.Command {
	var (
		dataDir        string
		acceptUnpinned bool
		dryRun         bool
	)
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Start a hub CA rotation",
		Long: "Start a hub CA rotation on the leader: it makes a new CA, which never leaves the hubs' data dirs,\n" +
			"and every hub fetches its key and a node certificate of it over the cluster's mutual TLS. Agents get\n" +
			"a certificate of the new CA when they next connect. Every hub must be up and at the store schema that\n" +
			"records rotations. Certificates without a recorded fingerprint refuse the rotation unless\n" +
			"--accept-unpinned: their holders are cut off when the rotation finishes. Run it on the leader's host\n" +
			"while its hub runs; finish it with `hearth cluster ca finish`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClusterCARotate(cmd.Context(), dataDir, acceptUnpinned, dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&acceptUnpinned, "accept-unpinned", false,
		"rotate although some certificates cannot be renewed; their holders are cut off at the finish")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the plan, decide and audit the action without doing it")
	return cmd
}

func runClusterCARotate(ctx context.Context, dataDir string, acceptUnpinned, dryRun bool, out io.Writer) error {
	st, cc, err := openClusterControl(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	defer cc.Close()
	opts := cluster.RotateOptions{AcceptUnpinned: acceptUnpinned}
	plan, err := cc.RotateCA(ctx, cluster.RotateOptions{AcceptUnpinned: acceptUnpinned, DryRun: true})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HUB\tPINNED NODE CERTIFICATE\t")
	for _, id := range sortedKeys(plan.Pins) {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t\n", id, plan.Pins[id])
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	for _, u := range plan.Unpinned {
		_, _ = fmt.Fprintf(out, "Not renewed, cut off at the finish: %s %s (serial %s)\n", u.Kind, u.ID, u.Serial)
	}
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.ClusterCARotate,
		Target: "hub CA",
		Detail: map[string]any{"hubs": len(plan.Pins), "unpinned": len(plan.Unpinned), "accept_unpinned": acceptUnpinned},
	}, func(ctx context.Context) error {
		plan, err = cc.RotateCA(ctx, opts)
		return err
	})
	if err != nil || !done {
		return err
	}
	_, err = fmt.Fprintf(out, "Started the hub CA rotation to %s. Hubs and agents renew on their own; check\n"+
		"`hearth cluster ca status`, then run `hearth cluster ca finish`.\n", plan.NewCAFP)
	return err
}

func newClusterCAFinishCmd() *cobra.Command {
	var (
		dataDir string
		force   bool
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   "finish",
		Short: "Finish the hub CA rotation and drop the old CA",
		Long: "Finish the hub CA rotation on the leader: once every hub holds the new CA, every hub serves it, the\n" +
			"stored secrets are re-sealed with its key, and every hub drops the old CA and deletes its key. From\n" +
			"then on nothing of the old CA is trusted. It refuses while agents or hubs hold only old-CA\n" +
			"certificates, unless --force, which cuts them off: such an agent has to enroll again, a hub to join\n" +
			"again. Run it on the leader's host while its hub runs.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClusterCAFinish(cmd.Context(), dataDir, force, dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&force, "force", false, "finish although agents or hubs still hold only old-CA certificates")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the plan, decide and audit the action without doing it")
	return cmd
}

func runClusterCAFinish(ctx context.Context, dataDir string, force, dryRun bool, out io.Writer) error {
	st, cc, err := openClusterControl(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	defer cc.Close()
	plan, err := cc.FinishCA(ctx, cluster.FinishOptions{Force: force, DryRun: true})
	if err != nil {
		return err
	}
	for _, id := range plan.OldHubs {
		_, _ = fmt.Fprintf(out, "Cut off: hub %s holds only old-CA certificates and has to join again.\n", id)
	}
	for _, id := range plan.OldDevices {
		_, _ = fmt.Fprintf(out, "Cut off: device %s holds only an old-CA certificate and has to enroll again.\n", id)
	}
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.ClusterCAFinish,
		Target: "hub CA " + plan.NewCAFP,
		Detail: map[string]any{"force": force, "cut_off_devices": plan.OldDevices, "cut_off_hubs": plan.OldHubs},
	}, func(ctx context.Context) error {
		if _, err := fmt.Fprintln(out, "Finishing: waiting for every hub to serve the new CA..."); err != nil {
			return err
		}
		plan, err = cc.FinishCA(ctx, cluster.FinishOptions{Force: force})
		return err
	})
	if err != nil || !done {
		return err
	}
	_, err = fmt.Fprintf(out, "Finished: every hub serves %s only; %d sealed secrets re-sealed. Backups taken before\n"+
		"now still hold the old CA key.\n", plan.NewCAFP, plan.Resealed)
	return err
}

func newClusterCAStatusCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the hub CA rotation and every hub's side of it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClusterCAStatus(cmd.Context(), dataDir, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func runClusterCAStatus(ctx context.Context, dataDir string, out io.Writer) error {
	if !cluster.IsMember(dataDir) {
		return errors.New("hub CA rotation is for clusters: " + dataDir + " is a standalone hub")
	}
	cc, err := cluster.DialControl(dataDir)
	if err != nil {
		return err
	}
	defer cc.Close()
	s, err := cc.CAStatus(ctx)
	if err != nil {
		return err
	}
	if s.Rotation == nil {
		_, _ = fmt.Fprintln(out, "No hub CA rotation so far.")
	} else {
		_, _ = fmt.Fprintf(out, "Rotation to %s: %s (since %s)\n", s.Rotation.NewCAFP, s.Rotation.Stage,
			s.Rotation.UpdatedAt.Local().Format(time.DateTime))
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HUB\tSERVES\tNEXT CA\tNEXT KEY\tNEXT NODE CERT\t")
	for _, h := range s.Hubs {
		if h.Error != "" {
			_, _ = fmt.Fprintf(tw, "%s\tunknown: %s\t\t\t\t\n", h.ID, h.Error)
			continue
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t\n", h.ID, short(h.Info.ServingFP), short(h.Info.NextFP),
			yesNo(h.Info.HasNextKey), yesNo(h.Info.HasNextCert))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	if len(s.OldDevices) > 0 {
		_, _ = fmt.Fprintf(out, "Devices not renewed yet (cut off by a forced finish): %v\n", s.OldDevices)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// short abbreviates a fingerprint for a table.
func short(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	if fp == "" {
		return "-"
	}
	return fp
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
