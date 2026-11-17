// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/agent"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Run or manage the Hearth agent on this device"}
	cmd.AddCommand(newAgentJoinCmd(), newAgentRunCmd())
	return cmd
}

func newAgentRunCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Connect to the hub and keep reporting this device",
		Long: "Connect to the hub this device joined and keep the connection up: report host facts,\n" +
			"send heartbeats and reconnect with backoff when the hub is unreachable. Stops on SIGINT/SIGTERM.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return agent.Run(cmd.Context(), agent.Config{
				DataDir: dataDir,
				Version: cmd.Root().Version,
				Log:     newLogger(cmd.ErrOrStderr()),
			})
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("agent"), "agent data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func newAgentJoinCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "join <hub-url> <token>",
		Short: "Enroll this device with a hub",
		Long: "Enroll this device with a hub using a token from `hearth token create`.\n" +
			"The hub is verified against the CA fingerprint in the token before the token is sent.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := agent.Join(cmd.Context(), args[0], args[1], dataDir, hostnameOr(""))
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enrolled as device %s; identity stored in %s.\n", id, dataDir); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("agent"), "agent data directory (env HEARTH_DATA_DIR)")
	return cmd
}
