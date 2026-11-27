// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newDeviceCapabilitiesCmd() *cobra.Command {
	var (
		dataDir string
		sets    []string
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   "capabilities <device-id>",
		Short: "Show or change what the hub may do on a device",
		Long: "Show a device's capabilities: what the hub sets for it, what its agent's --allow-* flags grant\n" +
			"(the hub cannot take that away), and what the agent reports in effect, their union. Run it on a\n" +
			"hub host. --set changes what the hub sets, as the device's Capabilities card in the web UI does;\n" +
			"the agent applies it within one heartbeat, without a restart. Repeat --set for several:\n\n" +
			"  shell, probe, net-edges  on | off\n" +
			"  docker                   on (list, logs, start, stop, restart) | read (list, logs) | off\n" +
			"  logs, restart            on (every source or service) | off | manager:name,... (systemd,\n" +
			"                           systemd-user or docker; a name may be a glob such as docker:*)\n" +
			"  scan                     on (the private IPv4 ranges) | off | CIDR,...\n" +
			"  exec                     off | /absolute/path,... (no on: name each program)\n" +
			"  plugins                  off | name[:class][@latest],... (the plugins uploaded with `hearth\n" +
			"                           plugin upload` it may install and run, each up to a class of command:\n" +
			"                           read (the default), safe or dangerous). Each grant pins one release,\n" +
			"                           program and manifest, by its digest: a new grant pins the release\n" +
			"                           uploaded now, and one already set keeps its release until @latest\n" +
			"                           moves it to the one uploaded now\n\n" +
			"Raising shell, exec, restart, Docker control or a plugin, or moving a plugin to another release,\n" +
			"is the dangerous policy action\n" +
			"device.capabilities.raise; anything else is device.capabilities.set. Both are audited. A device\n" +
			"whose agent runs with --local-ceiling ignores what the hub sets.",
		Example: "  hearth device capabilities pi\n" +
			"  hearth device capabilities pi --set logs=on --set docker=read\n" +
			"  hearth device capabilities pi --set exec=/usr/bin/df,/usr/sbin/reboot --set shell=off\n" +
			"  hearth device capabilities pi --set plugins=go-lamp:safe\n" +
			"  hearth device capabilities pi --set plugins=go-lamp:safe@latest",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeviceCapabilities(cmd.Context(), dataDir, args[0], sets, dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringArrayVar(&sets, "set", nil, "capability=value to set; repeatable (see above)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the change without making it")
	return cmd
}

func runDeviceCapabilities(ctx context.Context, dataDir, deviceID string, sets []string, dryRun bool, out io.Writer) error {
	dbPath := filepath.Join(dataDir, dbFile)
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("open hub database: %w (has `hearth hub` been started with --data-dir %s?)", err, dataDir)
	}
	st, err := openHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	d, err := st.Devices().Get(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no device %s", deviceID)
	}
	if err != nil {
		return err
	}
	caps, err := hub.DeviceCapabilities(ctx, st, d)
	if err != nil {
		return err
	}
	if len(sets) == 0 {
		return printCapabilities(out, d, caps)
	}
	next := caps.Hub
	for _, s := range sets {
		key, value, ok := strings.Cut(s, "=")
		if !ok {
			return fmt.Errorf("--set %q: want capability=value", s)
		}
		if err := hub.SetCapability(&next, strings.TrimSpace(key), value); err != nil {
			return fmt.Errorf("--set: %w", err)
		}
	}
	if err := hub.PinPluginGrants(ctx, st, d, caps.Hub, &next); err != nil {
		return fmt.Errorf("--set: %w", err)
	}
	c, err := hub.NormalizeCeiling(next)
	if err != nil {
		return fmt.Errorf("--set: %w", err)
	}
	body, err := protojson.Marshal(c)
	if err != nil {
		return err
	}
	change := hub.ChangeOf(caps.Hub.Proto(), c)
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: change.Action, Target: deviceID, Detail: change.Detail(deviceID),
		Precheck: func(context.Context) error {
			if caps.Locked {
				return hub.ErrCeilingLocked
			}
			return hub.CeilingKnown(caps)
		},
	}, func(ctx context.Context) error {
		return st.DeviceCeilings().Set(ctx, deviceID, body, policy.ActorAdmin+"/"+adminActor(), time.Now())
	})
	if errors.Is(err, store.ErrSchemaTooOld) {
		return errors.New("the hub cluster's database predates managed capabilities: upgrade every hub of the cluster first")
	}
	if err != nil || !done {
		return err
	}
	if _, err := fmt.Fprintf(out, "Set the capabilities of device %s. Its agent applies them within one heartbeat.\n", deviceID); err != nil {
		return err
	}
	if !caps.Manageable {
		_, err = fmt.Fprintln(out, "Its agent is too old to take them: upgrade it (protocol minor 10).")
	}
	return err
}

// printCapabilities shows caps as a table: what the hub sets, what the
// device's flags grant, and what is in effect.
func printCapabilities(out io.Writer, d store.Device, caps hub.CapabilitiesJSON) error {
	note := "takes its capabilities from the hub"
	switch {
	case caps.Locked:
		note = "runs with --local-ceiling: only its flags count"
	case caps.Effective == nil:
		note = "has not reported yet"
	case !caps.Manageable:
		note = "is too old to take capabilities from the hub: upgrade it"
	}
	if _, err := fmt.Fprintf(out, "Device %s: its agent %s.\n", d.ID, note); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CAPABILITY\tHUB SETS\tDEVICE FLAGS\tIN EFFECT")
	for _, k := range hub.CapabilityKeys {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k, capValue(&caps.Hub, k), capValue(caps.Local, k), capValue(caps.Effective, k))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, g := range caps.Hub.Plugins {
		for _, r := range caps.PluginReleases {
			if r.Name == g.Name && r.Digest != g.Digest {
				if _, err := fmt.Fprintf(out, "Plugin %s: release %s (%.12s) was uploaded; approve it with --set plugins=%s:%s@latest.\n",
					g.Name, r.Version, r.Digest, g.Name, g.Class); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// capValue is capability k of c as --set takes it, or "-" for no c.
func capValue(c *hub.Ceiling, k string) string {
	if c == nil {
		return "-"
	}
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	list := func(l, all []string) string {
		switch {
		case len(l) == 0:
			return "off"
		case all != nil && slices.Equal(l, all):
			return "on"
		}
		return strings.Join(l, ",")
	}
	switch k {
	case "shell":
		return onOff(c.Shell)
	case "probe":
		return onOff(c.Probe)
	case "net-edges":
		return onOff(c.NetEdges)
	case "docker":
		switch {
		case c.Docker:
			return "on"
		case c.DockerRead:
			return "read"
		}
		return "off"
	case "logs":
		return list(c.Logs, hub.AllLogs)
	case "restart":
		return list(c.Restart, hub.AllRestart)
	case "scan":
		return list(c.Scan, hub.AllScan)
	case "exec":
		return list(c.Exec, nil)
	case "plugins":
		if len(c.Plugins) == 0 {
			return "off"
		}
		grants := make([]string, len(c.Plugins))
		for i, g := range c.Plugins {
			grants[i] = g.Name + ":" + string(g.Class)
			if g.Digest != "" {
				grants[i] += "@" + g.Digest[:min(12, len(g.Digest))]
			}
		}
		return strings.Join(grants, ",")
	}
	return "?"
}
