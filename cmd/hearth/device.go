// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newDeviceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "device", Short: "Manage enrolled devices"}
	cmd.AddCommand(newDeviceRevokeCmd())
	return cmd
}

func newDeviceRevokeCmd() *cobra.Command {
	var (
		dataDir string
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   "revoke <device-id>",
		Short: "Revoke a device's certificates so it can no longer connect",
		Long: "Revoke every certificate issued to a device. Run it on the hub host. A connected agent is\n" +
			"disconnected at its next heartbeat (within 10 s) and the device is marked offline; the agent\n" +
			"then exits instead of reconnecting. To bring the device back, re-enroll it with `hearth agent join`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeviceRevoke(cmd.Context(), dataDir, args[0], dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the action without doing it")
	return cmd
}

func runDeviceRevoke(ctx context.Context, dataDir, deviceID string, dryRun bool, out io.Writer) error {
	dbPath := filepath.Join(dataDir, dbFile)
	// Fail on a wrong data dir instead of creating an empty database there.
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("open hub database: %w (has `hearth hub` been started with --data-dir %s?)", err, dataDir)
	}
	st, err := openHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	var n int
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.DeviceRevoke,
		Target: deviceID,
	}, func(ctx context.Context) error {
		var err error
		n, err = st.Certs().RevokeDevice(ctx, deviceID, time.Now())
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("device %s has no certificates", deviceID)
	}
	if err != nil || !done {
		return err
	}
	if _, err := fmt.Fprintf(out, "Revoked %d certificate(s) of device %s.\n", n, deviceID); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}
