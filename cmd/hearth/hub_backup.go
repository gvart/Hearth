// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/s3"
	"github.com/gvart/hearth/internal/store"
)

// scheduledBackupOptions are the hub's flags for scheduled backups to an
// S3-compatible bucket. They are off unless interval is set.
type scheduledBackupOptions struct {
	interval       time.Duration
	keep           int
	passphraseFile string
	endpoint       string
	region         string
	bucket         string
	prefix         string
	virtualHost    bool
	accessKeyID    string
	// secretKey is HEARTH_BACKUP_S3_SECRET_ACCESS_KEY; secretKeyFile the file
	// that may hold it instead.
	secretKey     string
	secretKeyFile string
	// notify is the notification channel told about a failed backup.
	notify string
}

func addBackupFlags(cmd *cobra.Command, o *scheduledBackupOptions) {
	f := cmd.Flags()
	f.DurationVar(&o.interval, "backup-interval", 0,
		"time between scheduled backups to an S3-compatible bucket, e.g. 24h (env HEARTH_BACKUP_INTERVAL; "+
			"default: off; see docs/backup.md)")
	f.IntVar(&o.keep, "backup-keep", backup.DefaultKeep,
		"scheduled backups to keep in the bucket; older ones are deleted (env HEARTH_BACKUP_KEEP)")
	f.StringVar(&o.passphraseFile, "backup-passphrase-file", os.Getenv("HEARTH_BACKUP_PASSPHRASE_FILE"),
		"file holding the passphrase of scheduled backups, mode 0600; keep it away from the bucket "+
			"(env HEARTH_BACKUP_PASSPHRASE_FILE)")
	f.StringVar(&o.endpoint, "backup-s3-endpoint", os.Getenv("HEARTH_BACKUP_S3_ENDPOINT"),
		"S3 API URL, e.g. https://s3.eu-central-1.amazonaws.com or http://minio.lan:9000 (env HEARTH_BACKUP_S3_ENDPOINT)")
	f.StringVar(&o.region, "backup-s3-region", envOr("HEARTH_BACKUP_S3_REGION", "us-east-1"),
		"region of the bucket (env HEARTH_BACKUP_S3_REGION)")
	f.StringVar(&o.bucket, "backup-s3-bucket", os.Getenv("HEARTH_BACKUP_S3_BUCKET"),
		"bucket of scheduled backups (env HEARTH_BACKUP_S3_BUCKET)")
	f.StringVar(&o.prefix, "backup-s3-prefix", envOr("HEARTH_BACKUP_S3_PREFIX", "hearth/"),
		"key prefix of scheduled backups; only backups under it are pruned (env HEARTH_BACKUP_S3_PREFIX)")
	f.BoolVar(&o.virtualHost, "backup-s3-virtual-host", false,
		"address the bucket as bucket.endpoint-host instead of endpoint/bucket (path style, the default)")
	f.StringVar(&o.accessKeyID, "backup-s3-access-key-id", os.Getenv("HEARTH_BACKUP_S3_ACCESS_KEY_ID"),
		"access key ID for the bucket (env HEARTH_BACKUP_S3_ACCESS_KEY_ID); the secret key comes from env "+
			"HEARTH_BACKUP_S3_SECRET_ACCESS_KEY or --backup-s3-secret-key-file")
	f.StringVar(&o.secretKeyFile, "backup-s3-secret-key-file", os.Getenv("HEARTH_BACKUP_S3_SECRET_KEY_FILE"),
		"file holding the bucket's secret access key, mode 0600 (env HEARTH_BACKUP_S3_SECRET_KEY_FILE)")
	f.StringVar(&o.notify, "backup-notify", os.Getenv("HEARTH_BACKUP_NOTIFY"),
		"notification channel to tell about a failed scheduled backup (env HEARTH_BACKUP_NOTIFY)")
}

// fromEnv reads the environment for the flags that are not strings.
func (o *scheduledBackupOptions) fromEnv(cmd *cobra.Command) error {
	o.secretKey = os.Getenv("HEARTH_BACKUP_S3_SECRET_ACCESS_KEY")
	if v := os.Getenv("HEARTH_BACKUP_INTERVAL"); v != "" && !cmd.Flags().Changed("backup-interval") {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("HEARTH_BACKUP_INTERVAL: %w", err)
		}
		o.interval = d
	}
	if v := os.Getenv("HEARTH_BACKUP_KEEP"); v != "" && !cmd.Flags().Changed("backup-keep") {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("HEARTH_BACKUP_KEEP: %w", err)
		}
		o.keep = n
	}
	return nil
}

// backupScheduler returns the scheduler of the hub's backups, or nil when
// --backup-interval is not set. It reads the passphrase and the secret key,
// and never logs them.
func backupScheduler(opts hubOptions, st *store.Store, pol *policy.Engine, n *notify.Notifier, clustered bool,
	log *slog.Logger,
) (*backup.Scheduler, error) {
	o := opts.backup
	if o.interval == 0 {
		if o.bucket != "" || o.passphraseFile != "" || o.endpoint != "" {
			return nil, errors.New("--backup-s3-bucket, --backup-s3-endpoint and --backup-passphrase-file need --backup-interval")
		}
		return nil, nil
	}
	switch {
	case o.interval < 0:
		return nil, errors.New("--backup-interval must be positive")
	case o.keep < 1:
		return nil, errors.New("--backup-keep must be at least 1")
	case o.endpoint == "" || o.bucket == "":
		return nil, errors.New("--backup-interval needs --backup-s3-endpoint and --backup-s3-bucket")
	case o.passphraseFile == "":
		return nil, errors.New("--backup-interval needs --backup-passphrase-file")
	case o.accessKeyID == "":
		return nil, errors.New("--backup-interval needs --backup-s3-access-key-id")
	case o.notify != "" && !n.Has(o.notify):
		return nil, fmt.Errorf("--backup-notify: no notification channel %q (see --notify-config)", o.notify)
	}
	prefix := strings.TrimPrefix(o.prefix, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	passphrase, err := readSecretFile(o.passphraseFile)
	if err != nil {
		return nil, fmt.Errorf("--backup-passphrase-file: %w", err)
	}
	if len(passphrase) < backup.MinPassphraseLen {
		return nil, fmt.Errorf("--backup-passphrase-file: the backup passphrase needs at least %d characters", backup.MinPassphraseLen)
	}
	secret, err := secretFrom(o.secretKey, o.secretKeyFile, "HEARTH_BACKUP_S3_SECRET_ACCESS_KEY", "--backup-s3-secret-key-file")
	if err != nil {
		return nil, err
	}
	bucket, err := s3.New(s3.Config{
		Endpoint: o.endpoint, Region: o.region, Bucket: o.bucket, VirtualHost: o.virtualHost,
		AccessKeyID: o.accessKeyID, SecretAccessKey: secret,
	})
	if err != nil {
		return nil, fmt.Errorf("--backup-s3-endpoint: %w", err)
	}
	log.Info("scheduled backups on", "bucket", o.bucket, "prefix", prefix, "interval", o.interval, "keep", o.keep,
		"notify", o.notify)
	return backup.NewScheduler(backup.ScheduleConfig{
		Interval: o.interval, Keep: o.keep, Bucket: bucket, BucketName: o.bucket, Prefix: prefix,
		Passphrase: passphrase,
		Backup: backup.CreateOptions{
			DataDir: opts.dataDir, Store: st, NotifyConfig: opts.notifyConfig,
			AutomationsDir: opts.automationsDir, RunbooksDir: opts.runbooksDir,
			HearthVersion: opts.version, Clustered: clustered,
		},
		Policy: pol, Notifier: n, Channel: o.notify, Log: log,
	}), nil
}
