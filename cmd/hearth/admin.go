// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

func newAdminCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "admin", Short: "Manage the hub's admin account"}
	cmd.AddCommand(newAdminSetPasswordCmd())
	return cmd
}

func newAdminSetPasswordCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "set-password",
		Short: "Set or reset the admin password for the web UI and API",
		Long: "Set or reset the admin password. Run it on the hub host: it opens the hub's data dir directly.\n" +
			"The password is read from stdin (prompted twice, without echo, on a terminal).\n" +
			"Resetting the password logs out every session.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pw, err := readPassword(cmd.InOrStdin(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			return runAdminSetPassword(cmd.Context(), dataDir, pw, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func runAdminSetPassword(ctx context.Context, dataDir, password string, out io.Writer) error {
	dbPath := filepath.Join(dataDir, dbFile)
	// Fail on a wrong data dir instead of creating an empty database there.
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("open hub database: %w (has `hearth hub` been started with --data-dir %s?)", err, dataDir)
	}
	// Only a master writes the admin password, a global row (#382): a
	// storage-only member's copy would reach no other member.
	if cluster.IsMember(dataDir) {
		if _, err := os.Stat(filepath.Join(dataDir, pki.CAKeyFile)); err != nil {
			return errors.New("this hub is not a master of its cluster: set the password on a master's host, or in the web UI")
		}
	}
	st, err := openHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := hub.SetAdminPassword(ctx, st, policy.New(st.Audit()), adminActor(), password); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "Admin password set. Existing sessions have been logged out."); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// readPassword prompts twice without echo when in is a terminal, and otherwise
// reads the first line of in.
func readPassword(in io.Reader, prompt io.Writer) (string, error) {
	return readNewPassword(in, prompt, "New admin password: ")
}

// readNewPassword is readPassword with label as the first prompt.
func readNewPassword(in io.Reader, prompt io.Writer, label string) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		read := func(label string) (string, error) {
			_, _ = fmt.Fprint(prompt, label)
			b, err := term.ReadPassword(fd)
			_, _ = fmt.Fprintln(prompt)
			if err != nil {
				return "", fmt.Errorf("read password: %w", err)
			}
			return string(b), nil
		}
		pw, err := read(label)
		if err != nil {
			return "", err
		}
		again, err := read("Repeat password: ")
		if err != nil {
			return "", err
		}
		if pw != again {
			return "", errors.New("passwords do not match")
		}
		return pw, nil
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
