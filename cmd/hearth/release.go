// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/release"
)

// releaseMirrorEnv is the environment variable behind `hearth agent run
// --release-mirror`.
const releaseMirrorEnv = "HEARTH_RELEASE_MIRROR"

func newReleaseCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "release", Short: "Work with Hearth releases"}
	cmd.AddCommand(newReleaseMirrorCmd())
	return cmd
}

func newReleaseMirrorCmd() *cobra.Command {
	var from string
	cmd := &cobra.Command{
		Use:   "mirror <tag> <dir>",
		Short: "Copy a release into a local release mirror, for devices that cannot reach GitHub",
		Long: "Download release <tag> into <dir>/<tag>/: its checksums.txt, the signatures of checksums.txt\n" +
			"(checksums.txt.sig and checksums.txt.sigstore.json) and every archive checksums.txt lists. The\n" +
			"signature is checked with the Hearth release key compiled into this binary before anything is\n" +
			"written, and each archive against its SHA-256; an archive already there is kept. Serve <dir>\n" +
			"over HTTP and point agents at it with `hearth agent run --release-mirror <URL>` (install.sh\n" +
			"--release-mirror writes that into the agent's service).",
		Example: "  hearth release mirror v0.0.1-rc.12 /srv/hearth-releases\n" +
			"  cd /srv/hearth-releases && python3 -m http.server 8000",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := release.MirrorBase(from)
			if err != nil {
				return fmt.Errorf("--from: %w", err)
			}
			key, err := release.TrustedKey()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			return release.Mirror(cmd.Context(), release.HTTPClient(), key, base, args[0], args[1], func(s string) {
				_, _ = fmt.Fprintln(out, s)
			})
		},
	}
	cmd.Flags().StringVar(&from, "from", release.BaseURL, "where to download the release from, as <URL>/<tag>/<asset>: another mirror")
	return cmd
}
