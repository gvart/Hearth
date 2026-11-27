// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newDeviceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "device", Short: "Manage enrolled devices"}
	cmd.AddCommand(newDeviceRevokeCmd(), newDeviceHubCmd(), newDeviceCapabilitiesCmd(), newDeviceUpgradeCmd())
	return cmd
}

// deviceUpgradeWait bounds how long `hearth device upgrade` waits for the
// agent's upgrade, and deviceBackWait for it to come back on the new
// version.
const (
	deviceUpgradeWait = 6 * time.Minute
	deviceBackWait    = time.Minute
)

func newDeviceUpgradeCmd() *cobra.Command {
	var hubURL, version string
	cmd := &cobra.Command{
		Use:   "upgrade <device-id>",
		Short: "Upgrade a device's agent to the hub's version, or to --version",
		Long: "Asks the device's agent to upgrade itself: it downloads the release archive from GitHub, checks it\n" +
			"against the release's checksums.txt and that file's signature, replaces its binary (keeping the old\n" +
			"one as hearth.prev) and restarts; if the new version reaches no hub, the agent puts the old one back.\n" +
			"This uses the hub's API with a signed-in session: the admin password comes from\n" +
			"HEARTH_ADMIN_PASSWORD or is asked for. An agent older than remote upgrades is upgraded once by\n" +
			"re-running the installer on the device; its page in the web UI shows the command.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lines := &lineReader{in: cmd.InOrStdin(), buf: bufio.NewReader(cmd.InOrStdin()), prompt: cmd.ErrOrStderr()}
			// Signing in enters the password: it counts as entering it again.
			c, err := loginRunbookClient(cmd.Context(), hubURL, lines)
			if err != nil {
				return err
			}
			c.http.Timeout = deviceUpgradeWait
			return c.upgradeDevice(cmd.Context(), args[0], version, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&hubURL, "hub-url", envOr("HEARTH_HUB_URL", "http://127.0.0.1:"+defaultHTTPPort),
		"the hub's web address (env HEARTH_HUB_URL)")
	cmd.Flags().StringVar(&version, "version", "", "the release to upgrade to, such as v0.1.0 (default: the hub's version)")
	return cmd
}

// upgradeDevice asks for the upgrade, then waits for the agent to come back
// on the new version.
func (c *runbookClient) upgradeDevice(ctx context.Context, id, version string, out io.Writer) error {
	_, _ = fmt.Fprintf(out, "Upgrading the agent of %s…\n", id)
	var done hub.UpgradeJSON
	path := "/api/v1/devices/" + url.PathEscape(id)
	if err := c.do(ctx, http.MethodPost, path+"/upgrade", hub.UpgradeJSON{Version: version}, &done); err != nil {
		return fmt.Errorf("upgrade %s: %w", id, err)
	}
	_, _ = fmt.Fprintf(out, "The agent replaced its binary (%s → %s) and is restarting.\n", done.From, done.Version)
	ctx, cancel := context.WithTimeout(ctx, deviceBackWait)
	defer cancel()
	for {
		var d hub.DeviceJSON
		if err := c.do(ctx, http.MethodGet, path, nil, &d); err == nil && d.Status == store.StatusOnline &&
			d.AgentVersion != nil && d.AgentVersion.Agent == done.Version {
			_, err := fmt.Fprintf(out, "Device %s is back on %s.\n", id, done.Version)
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the agent of %s did not come back on %s within %s: check its service on the device", id, done.Version, deviceBackWait)
		case <-time.After(time.Second):
		}
	}
}

func newDeviceHubCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "hub <device-id>",
		Short: "Show whether a device is a hub of the cluster too, and its roles",
		Long: "Show the cluster member a device became: the hub that joined with a join token minted for the\n" +
			"device (at its enrollment, or on its page in the web UI), with its roles and state; or that the\n" +
			"device is an agent only. Run it on a master's host. Change the roles with `hearth cluster promote`\n" +
			"and `hearth cluster demote`, take the hub out with `hearth cluster remove`; make a device a hub on\n" +
			"its page in the web UI (docs/cluster.md).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeviceHub(cmd.Context(), dataDir, args[0], cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func runDeviceHub(ctx context.Context, dataDir, deviceID string, out io.Writer) error {
	cc, err := dialHub(dataDir)
	if err != nil {
		return err
	}
	defer cc.Close()
	st, err := openHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.Devices().Get(ctx, deviceID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no device %s", deviceID)
		}
		return err
	}
	node, err := st.JoinTokens().HubOf(ctx, deviceID)
	if err != nil {
		return err
	}
	if node == "" {
		_, err := fmt.Fprintf(out, "Device %s is an agent only: no hub of the cluster.\n", deviceID)
		return err
	}
	status, err := cc.Status(ctx)
	if err != nil {
		return err
	}
	for _, m := range status.Members {
		if m.ID == node {
			_, err := fmt.Fprintf(out, "Device %s is hub %s: roles %s (allowed %s), %s.\n",
				deviceID, node, m.Roles&cluster.HubRoles, m.AllowedRoles&cluster.HubRoles, m.State)
			return err
		}
	}
	_, err = fmt.Fprintf(out, "Device %s is hub %s, which this hub does not see in the gossip.\n", deviceID, node)
	return err
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
