// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
)

// joinTokenEnvVar names the environment variable `hearth agent make-hub`
// reads the cluster join token from, as `hearth hub --join` does.
const joinTokenEnvVar = "HEARTH_JOIN_TOKEN" //nolint:gosec // G101: the variable's name, not a credential

// newAgentMakeHubCmd writes the join of a device an admin makes a hub on its
// page (#332): the installer runs it with --make-hub, then starts the hub
// service, which joins with the file.
func newAgentMakeHubCmd() *cobra.Command {
	var hubDataDir string
	cmd := &cobra.Command{
		Use:   "make-hub <join-url> [-]",
		Short: "Make this enrolled device a hub with a join token from its page in the web UI",
		Long: "Write the join a device's page in the web UI made for this device (\"Make this device a hub\")\n" +
			"into <hub-data-dir>/join, for `hearth hub --join-file`. The installer runs it for\n" +
			"`install.sh --make-hub <join-url>`, then installs and starts the hub service.\n" +
			"The join token comes from " + joinTokenEnvVar + ", or from the first line of stdin with -.\n" +
			"Unlike a hub at enrollment, a macOS device qualifies; every device still needs a 64-bit CPU,\n" +
			"1.5 GiB of memory and 2 GiB free for the hub's data.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := strings.TrimSpace(os.Getenv(joinTokenEnvVar))
			if err := os.Unsetenv(joinTokenEnvVar); err != nil {
				return fmt.Errorf("unset %s: %w", joinTokenEnvVar, err)
			}
			if len(args) == 2 {
				if args[1] != "-" {
					return errors.New("the join token goes in " + joinTokenEnvVar + " or on stdin (-), never in argv")
				}
				var err error
				if token, err = readToken(cmd.InOrStdin()); err != nil {
					return err
				}
			}
			return runAgentMakeHub(cmd, hubDataDir, args[0], token, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&hubDataDir, "hub-data-dir", defaultDataDir("hub"), "the hub's data directory")
	return cmd
}

func runAgentMakeHub(cmd *cobra.Command, hubDataDir, joinURL, token string, out io.Writer) error {
	if !strings.HasPrefix(joinURL, "https://") {
		return errors.New("the join URL is the master's agent URL, https://<hub>:7443")
	}
	if token == "" {
		return errors.New("no join token: set " + joinTokenEnvVar + "=<token>, or pass - and the token on stdin")
	}
	if _, err := pki.ParseJoinToken(token); err != nil {
		return fmt.Errorf("the join token: %w", err)
	}
	if _, err := os.Stat(filepath.Join(hubDataDir, pki.CACertFile)); err == nil {
		return fmt.Errorf("%s holds a hub already: if it was removed from the cluster, delete %s and run this again", hubDataDir, hubDataDir)
	}
	o, err := cluster.LocalHubOffer(cmd.Context(), hubDataDir)
	if err == nil {
		err = cluster.HubChosen(o)
	}
	if err != nil {
		return fmt.Errorf("this device cannot be a hub: %w", err)
	}
	path := filepath.Join(hubDataDir, cluster.JoinFileName)
	if err := cluster.WriteJoinFile(path, cluster.JoinFile{URL: joinURL, Token: token}); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "This device becomes a hub: `hearth hub --join-file %s` joins the cluster.\n", path)
	return err
}
