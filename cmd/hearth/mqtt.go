// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/mqtt"
)

func newMQTTCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "mqtt", Short: "Helpers for the hub's embedded MQTT broker (see docs/mqtt.md)"}
	cmd.AddCommand(&cobra.Command{
		Use:   "hash-password",
		Short: "Print the password_hash of an MQTT user",
		Long: "Read a password, without echo on a terminal or as the first line of stdin, and print its\n" +
			"bcrypt hash for a user's password_hash in the MQTT clients file. It changes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pw, err := readNewPassword(cmd.InOrStdin(), cmd.ErrOrStderr(), "MQTT password: ")
			if err != nil {
				return err
			}
			h, err := mqtt.HashPassword(pw)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), h); err != nil {
				return fmt.Errorf("write hash: %w", err)
			}
			return nil
		},
	})
	return cmd
}
