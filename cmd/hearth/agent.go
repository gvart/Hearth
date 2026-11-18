// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/agent"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Run or manage the Hearth agent on this device"}
	cmd.AddCommand(newAgentJoinCmd(), newAgentRunCmd())
	return cmd
}

func newAgentRunCmd() *cobra.Command {
	var (
		dataDir string
		ceiling agent.Ceiling
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Connect to the hub and keep reporting this device",
		Long: "Connect to the hub this device joined and keep the connection up: report host facts,\n" +
			"send heartbeats and reconnect with backoff when the hub is unreachable. Stops on SIGINT/SIGTERM.\n\n" +
			"--allow-exec and --allow-restart are this device's capability ceiling: the only commands and\n" +
			"services the hub (its automations) may run or restart here. Without them it may run nothing.",
		Example: "  hearth agent run --allow-restart systemd:pihole-FTL.service --allow-restart docker:jellyfin \\\n" +
			"    --allow-exec /usr/bin/df",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, e := range ceiling.Restart {
				if err := agent.ParseRestart(e); err != nil {
					return fmt.Errorf("--allow-restart: %w", err)
				}
			}
			return agent.Run(cmd.Context(), agent.Config{
				DataDir: dataDir,
				Version: cmd.Root().Version,
				Log:     newLogger(cmd.ErrOrStderr()),
				Ceiling: ceiling,
			})
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("agent"), "agent data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringArrayVar(&ceiling.Exec, "allow-exec", nil,
		"program the hub may run here, matched exactly against the command's first word; repeatable")
	cmd.Flags().StringArrayVar(&ceiling.Restart, "allow-restart", nil,
		"service the hub may restart here, as systemd:UNIT, systemd-user:UNIT or docker:CONTAINER; repeatable")
	return cmd
}

func newAgentJoinCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "join <hub-url> [<token> | -]",
		Short: "Enroll this device with a hub",
		Long: "Enroll this device with a hub using a token from `hearth token create`.\n" +
			"The hub is verified against the CA fingerprint in the token before the token is sent.\n" +
			"The token comes from the " + tokenEnv + " environment variable, or from the first line of\n" +
			"stdin when the token argument is -. Both keep it out of argv, which any local user can read\n" +
			"with ps; a token argument still works but warns for that reason.",
		Example: "  " + tokenEnv + "=<token> hearth agent join https://hub.lan:7443",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := joinToken(cmd, args[1:])
			if err != nil {
				return err
			}
			id, err := agent.Join(cmd.Context(), args[0], token, dataDir, hostnameOr(""))
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

// tokenEnv names the environment variable `hearth agent join` reads the
// enrollment token from.
const tokenEnv = "HEARTH_TOKEN"

// joinToken returns the enrollment token from the optional token argument
// (- reads stdin) or else from $HEARTH_TOKEN. It always unsets HEARTH_TOKEN,
// so no process started later inherits the token.
func joinToken(cmd *cobra.Command, args []string) (string, error) {
	env := strings.TrimSpace(os.Getenv(tokenEnv))
	if err := os.Unsetenv(tokenEnv); err != nil {
		return "", fmt.Errorf("unset %s: %w", tokenEnv, err)
	}
	switch {
	case len(args) == 0:
		if env == "" {
			return "", errors.New("no enrollment token: set " + tokenEnv + "=<token>, or pass - and the token on stdin")
		}
		return env, nil
	case args[0] == "-":
		return readToken(cmd.InOrStdin())
	default:
		// Best effort: a warning that cannot be written must not fail the join.
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: a token argument is visible to other local users (ps); pass it as "+
			tokenEnv+"=<token> instead")
		return args[0], nil
	}
}

// maxTokenLine bounds the stdin read; real tokens are about 100 bytes.
const maxTokenLine = 4 << 10

// readToken reads an enrollment token from the first line of in.
func readToken(in io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(in, maxTokenLine)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read token from stdin: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", errors.New("no token on stdin (token argument was -)")
	}
	return token, nil
}
