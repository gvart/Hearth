// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// passphraseEnv names the environment variable holding the backup passphrase.
const passphraseEnv = "HEARTH_BACKUP_PASSPHRASE"

type backupOptions struct {
	dataDir        string
	notifyConfig   string
	automationsDir string
	runbooksDir    string
}

func newBackupCmd() *cobra.Command {
	opts := backupOptions{}
	cmd := &cobra.Command{
		Use:   "backup <file>",
		Short: "Write an encrypted backup of this hub",
		Long: "Write the hub's CA, database, policy.yaml, notify.yaml, automations and runbooks to an encrypted file.\n" +
			"Run it on the hub host; the hub may keep running. On a cluster member the hub must be running.\n\n" +
			"The file holds the CA private key and every credential, so it is always encrypted. The passphrase\n" +
			"comes from " + passphraseEnv + " or a prompt, and is needed to restore: without it the backup\n" +
			"is lost. See docs/backup.md.",
		Example: "  hearth backup /mnt/nas/hearth-$(date +%F).hbk",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := backup.CheckSource(opts.dataDir, args[0]); err != nil {
				return err
			}
			passphrase, err := readPassphrase(cmd.InOrStdin(), cmd.ErrOrStderr(), true)
			if err != nil {
				return err
			}
			if len(passphrase) < backup.MinPassphraseLen {
				return fmt.Errorf("the backup passphrase needs at least %d characters", backup.MinPassphraseLen)
			}
			ctx, stop := withHangup(cmd.Context())
			defer stop()
			return runBackup(ctx, opts, args[0], passphrase, cmd.Root().Version, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&opts.notifyConfig, "notify-config", os.Getenv("HEARTH_NOTIFY_CONFIG"),
		"the hub's notification channels file, if not <data-dir>/notify.yaml (env HEARTH_NOTIFY_CONFIG)")
	cmd.Flags().StringVar(&opts.automationsDir, "automations-dir", "",
		"the hub's automations directory, if not <data-dir>/automations")
	cmd.Flags().StringVar(&opts.runbooksDir, "runbooks-dir", "",
		"the hub's runbooks directory, if not <data-dir>/runbooks")
	return cmd
}

// openBackupStore opens the hub database for a backup without ever migrating
// it: a newer binary must not upgrade the database of a running older hub.
// Reads come from the local file; on a cluster member the audit entry goes
// through the running hub.
func openBackupStore(ctx context.Context, dataDir string) (*store.Store, error) {
	if cluster.IsMember(dataDir) {
		return openHubStore(ctx, dataDir)
	}
	return store.Open(ctx, filepath.Join(dataDir, dbFile), store.WithoutUpgrade())
}

func runBackup(ctx context.Context, opts backupOptions, output, passphrase, version string, out io.Writer) error {
	st, err := openBackupStore(ctx, opts.dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	// A member's database holds only its shards: the running hub copies
	// the whole cluster store into the backup's staging file.
	var snapshot func(context.Context, string) error
	clustered := false
	if cluster.IsMember(opts.dataDir) {
		cc, err := cluster.DialControl(opts.dataDir)
		if err != nil {
			return err
		}
		defer cc.Close()
		snapshot = cc.Snapshot
		status, err := cc.Status(ctx)
		if err != nil {
			return err
		}
		clustered = !status.Alone()
	}
	var m backup.Manifest
	created := false
	_, err = adminDo(ctx, opts.dataDir, st, out, false, policy.Request{
		Action: policy.HubBackup, Target: filepath.Base(output),
	}, func(ctx context.Context) error {
		var err error
		m, err = backup.Create(ctx, backup.CreateOptions{
			DataDir: opts.dataDir, Store: st, Output: output, Passphrase: passphrase,
			NotifyConfig: opts.notifyConfig, AutomationsDir: opts.automationsDir, RunbooksDir: opts.runbooksDir,
			HearthVersion: version, Clustered: clustered, Snapshot: snapshot,
		})
		created = err == nil
		return err
	})
	if err != nil {
		// A backup that could not be audited does not stay behind.
		if created {
			_ = os.Remove(output)
		}
		return err
	}
	if _, err := fmt.Fprintf(out, "Backup written to %s (schema %d).\n"+
		"Keep it and its passphrase safe and apart: the file holds the hub's CA key, and it cannot be restored without the passphrase.\n",
		output, m.Schema); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func newRestoreCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "restore <file>",
		Short: "Bring a hub back from a backup into an empty data dir",
		Long: "Restore a backup written by `hearth backup` into a data dir that is missing or empty. A data dir\n" +
			"that holds anything is refused. Enrolled agents reconnect by themselves if the hub comes back under\n" +
			"the same address.\n\n" +
			"The passphrase comes from " + passphraseEnv + " or a prompt. A backup of a cluster member comes\n" +
			"back as one hub: start it with --cluster to form a new cluster, and join the other hubs to it again.\n" +
			"See docs/backup.md.",
		Example: "  hearth restore --data-dir /var/lib/hearth/hub /mnt/nas/hearth-2026-11-19.hbk",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := backup.CheckDataDir(dataDir); err != nil {
				return fmt.Errorf("%w (restore never overwrites a hub: choose an empty --data-dir)", err)
			}
			passphrase, err := readPassphrase(cmd.InOrStdin(), cmd.ErrOrStderr(), false)
			if err != nil {
				return err
			}
			ctx, stop := withHangup(cmd.Context())
			defer stop()
			return runRestore(ctx, dataDir, args[0], passphrase, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory to restore into (env HEARTH_DATA_DIR)")
	return cmd
}

func runRestore(ctx context.Context, dataDir, input, passphrase string, out io.Writer) error {
	m, err := backup.Restore(ctx, backup.RestoreOptions{
		Input: input, Passphrase: passphrase, DataDir: dataDir,
		// No hub runs yet, so the decision and its audit entry go into the
		// restored database itself.
		BeforeCommit: func(ctx context.Context, st *store.Store) error {
			return policy.New(st.Audit()).Do(ctx, policy.Request{
				ActorKind: policy.ActorAdmin, ActorID: adminActor(),
				Action: policy.HubRestore, Target: filepath.Base(input),
			}, func(context.Context) error { return nil })
		},
	})
	if err != nil {
		return err
	}
	next := "Start the hub with `hearth hub --data-dir " + dataDir + "`, under the address its agents know."
	if m.Clustered {
		next = "This backup comes from a cluster. Stop the old hubs, then start this one without --join and\n" +
			"--cluster-seeds: it forms a new cluster of one. Join the other hubs to it with empty data dirs\n" +
			"(see \"Restoring a cluster\" in docs/backup.md)."
	}
	if m.NoCAKey {
		next = "This backup holds no CA key: the hub cannot start until " + filepath.Join(dataDir, pki.CAKeyFile) + " is there.\n" +
			"Restore a backup taken with `hearth backup` into an empty temporary dir and copy its " + pki.CAKeyFile + " here (mode 0600).\n" +
			"With no such backup, delete " + pki.CACertFile + " instead: the hub then creates a new CA, every agent has to enroll\n" +
			"again, and Kubernetes clusters, Proxmox servers, ESPHome devices, OpenWrt routers and OPNsense firewalls have to be added again. See docs/backup.md.\n" + next
	}
	if _, err := fmt.Fprintf(out, "Restored the backup of %s (Hearth %s, schema %d) into %s.\n%s\n",
		m.CreatedAt.Format("2006-01-02 15:04 MST"), m.HearthVersion, m.Schema, dataDir, next); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// withHangup ends ctx when the terminal goes away, so that a backup or restore
// removes its plaintext working files. Under nohup the signal stays ignored.
func withHangup(ctx context.Context) (context.Context, context.CancelFunc) {
	if signal.Ignored(syscall.SIGHUP) {
		return ctx, func() {}
	}
	return signal.NotifyContext(ctx, syscall.SIGHUP)
}

// readPassphrase returns the passphrase from the environment or, on a terminal,
// from a prompt without echo (twice when confirm is set). It never reads a
// passphrase from a flag or a pipe.
func readPassphrase(in io.Reader, prompt io.Writer, confirm bool) (string, error) {
	if v := os.Getenv(passphraseEnv); v != "" {
		return v, nil
	}
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", errors.New("no backup passphrase: set " + passphraseEnv + " or run this on a terminal")
	}
	fd := int(f.Fd())
	read := func(label string) (string, error) {
		_, _ = fmt.Fprint(prompt, label)
		b, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(prompt)
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		return string(b), nil
	}
	p, err := read("Backup passphrase: ")
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("the backup passphrase is empty")
	}
	if confirm {
		again, err := read("Repeat passphrase: ")
		if err != nil {
			return "", err
		}
		if p != again {
			return "", errors.New("passphrases do not match")
		}
	}
	return p, nil
}
