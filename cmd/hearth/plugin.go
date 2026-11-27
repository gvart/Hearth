// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Upload, list and remove the exec plugins devices may run",
		Long: "Exec plugins for devices: the hub hands each device's agent the program built for its platform,\n" +
			"pinned by SHA-256, once the device's capabilities allow that plugin\n" +
			"(`hearth device capabilities <device> --set plugins=name[:class]`). Run these on a hub host.\n" +
			"The web UI does the same under Settings, Device plugins.",
	}
	cmd.AddCommand(newPluginUploadCmd(), newPluginListCmd(), newPluginDeleteCmd())
	return cmd
}

func newPluginUploadCmd() *cobra.Command {
	var (
		dataDir, manifest, goos, arch string
		dryRun                        bool
	)
	cmd := &cobra.Command{
		Use:   "upload <program>",
		Short: "Upload a plugin's program for one platform",
		Long: "Store a plugin's program, built for one platform, and its manifest (plugin.yaml, protocol 1; see\n" +
			"docs/plugins.md). Uploading it again for the same platform replaces it. The upload is the dangerous\n" +
			"policy action plugin.binary.upload, audited with the program's SHA-256.",
		Example: "  GOOS=linux GOARCH=arm64 go build -o lamp ./examples/plugins/go-lamp\n" +
			"  hearth plugin upload lamp --manifest examples/plugins/go-lamp/plugin.yaml --os linux --arch arm64",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPluginUpload(cmd.Context(), dataDir, args[0], manifest, goos, arch, dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&manifest, "manifest", "", "the plugin's manifest, plugin.yaml (required)")
	cmd.Flags().StringVar(&goos, "os", runtime.GOOS, "the platform's operating system, as Go names it")
	cmd.Flags().StringVar(&arch, "arch", runtime.GOARCH, "the platform's architecture, as Go names it")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the upload without storing it")
	_ = cmd.MarkFlagRequired("manifest")
	return cmd
}

func runPluginUpload(ctx context.Context, dataDir, program, manifest, goos, arch string, dryRun bool, out io.Writer) error {
	if err := hub.CheckPlatform(goos, arch); err != nil {
		return err
	}
	mb, err := os.ReadFile(manifest)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	m, err := plugins.ParseManifest(mb)
	if err != nil {
		return err
	}
	st, err := openExistingHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	holder := ""
	if cluster.IsMember(dataDir) {
		if holder, err = cluster.NodeID(dataDir, "", ""); err != nil {
			return err
		}
	}
	f, err := os.Open(program)
	if err != nil {
		return fmt.Errorf("open program: %w", err)
	}
	defer f.Close()
	blobs := hub.NewPluginBlobs(dataDir)
	sum, size, err := blobs.Save(f)
	if err != nil {
		return err
	}
	u := hub.DevicePluginUpload{Manifest: m, OS: goos, Arch: arch, SHA256: sum, Size: size}
	req := u.Request()
	done, err := adminDo(ctx, dataDir, st, out, dryRun, req, func(ctx context.Context) error {
		return u.Save(ctx, st, holder, policy.ActorAdmin+"/"+adminActor(), time.Now())
	})
	if !done {
		if rerr := hub.RemoveDevicePluginBlob(context.WithoutCancel(ctx), st, blobs, sum); rerr != nil && err == nil {
			err = rerr
		}
	}
	if errors.Is(err, store.ErrSchemaTooOld) {
		return errors.New("the hub cluster's database predates device plugins: upgrade every hub of the cluster first")
	}
	if err != nil || !done {
		return err
	}
	_, err = fmt.Fprintf(out, "Uploaded plugin %s %s for %s/%s (%d bytes, sha256 %s).\n"+
		"Devices whose capabilities allow it install it at their next heartbeat.\n", m.Name, m.Version, goos, arch, size, sum)
	return err
}

func newPluginListCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the plugins uploaded for devices",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openExistingHubStore(cmd.Context(), dataDir)
			if err != nil {
				return err
			}
			defer st.Close()
			list, err := hub.ListDevicePlugins(cmd.Context(), st)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(list) == 0 {
				_, err := fmt.Fprintln(out, "No plugins uploaded. Upload one with `hearth plugin upload`.")
				return err
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "PLUGIN\tVERSION\tSIZE\tSHA256\tCOMMANDS")
			for _, p := range list {
				commands := make([]string, len(p.Commands))
				for i, c := range p.Commands {
					commands[i] = c.Name + ":" + string(c.Class)
				}
				_, _ = fmt.Fprintf(tw, "%s/%s/%s\t%s\t%d\t%s\t%s\n", p.Name, p.OS, p.Arch, p.Version, p.Size, p.SHA256[:12], strings.Join(commands, ","))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func newPluginDeleteCmd() *cobra.Command {
	var (
		dataDir string
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   "delete <name/os/arch>",
		Short: "Remove a plugin of one platform; devices remove it at their next heartbeat",
		Long:  "Remove an uploaded plugin of one platform, named as `hearth plugin list` shows it (name/os/arch).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPluginDelete(cmd.Context(), dataDir, args[0], dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the removal without removing it")
	return cmd
}

func runPluginDelete(ctx context.Context, dataDir, which string, dryRun bool, out io.Writer) error {
	name, platform, _ := strings.Cut(which, "/")
	goos, arch, _ := strings.Cut(platform, "/")
	id := store.DevicePluginID(name, goos, arch)
	st, err := openExistingHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	list, err := st.DevicePlugins().List(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(list, func(p store.DevicePlugin) bool { return p.ID == id })
	if i < 0 {
		return fmt.Errorf("no device plugin %s (see `hearth plugin list`)", which)
	}
	p := list[i]
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.PluginBinaryDelete, Target: p.Name,
		Detail: map[string]any{"plugin": p.Name, "version": p.Version, "os": p.OS, "arch": p.Arch, "sha256": p.SHA256},
	}, func(ctx context.Context) error { return st.DevicePlugins().Remove(ctx, id) })
	if err != nil || !done {
		return err
	}
	// The program held here goes, unless another plugin names it; a copy
	// fetched by another hub stays there.
	if err := hub.RemoveDevicePluginBlob(ctx, st, hub.NewPluginBlobs(dataDir), p.SHA256); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Removed plugin %s.\n", which)
	return err
}
