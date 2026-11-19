// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// DefaultKeep is how many scheduled backups the bucket keeps by default.
	DefaultKeep = 7
	// scheduleActor is the audit actor of scheduled backups: hub/backup.
	scheduleActor = "backup"
	// stampLayout names a scheduled backup by the time it was taken, so that
	// names sort by age.
	stampLayout = "20060102T150405Z"
	// maxRetryAfter bounds the wait before a failed backup is tried again.
	maxRetryAfter = time.Hour
	// maxRunTime bounds one backup, upload and prune, so that a bucket that
	// stops answering fails the run instead of stalling it.
	maxRunTime = time.Hour
)

// scheduledName matches the names scheduled backups are given under the
// prefix. Pruning never touches another object.
var scheduledName = regexp.MustCompile(`^hearth-\d{8}T\d{6}Z\.hbk$`)

// Bucket is where scheduled backups go: an S3-compatible bucket.
type Bucket interface {
	// Put uploads size bytes of body as key.
	Put(ctx context.Context, key string, body io.ReadSeeker, size int64) error
	// List returns the keys under prefix.
	List(ctx context.Context, prefix string) ([]string, error)
	// Delete removes key.
	Delete(ctx context.Context, key string) error
}

// Notifier tells the operator about a failed backup: notify.Notifier.
type Notifier interface {
	Send(ctx context.Context, channel, title, message string) error
}

// ScheduleConfig configures a Scheduler.
type ScheduleConfig struct {
	// Interval is the time between backups.
	Interval time.Duration
	// Keep is how many scheduled backups stay in the bucket; default
	// DefaultKeep.
	Keep int
	// Bucket receives the backups, under Prefix.
	Bucket Bucket
	// BucketName names the bucket in the audit log and in logs.
	BucketName string
	// Prefix is the key prefix of the backups, such as "hearth/".
	Prefix string
	// Passphrase encrypts the backups. It is never logged or audited.
	Passphrase string
	// Backup is what each backup holds: DataDir, Store and the rest, and
	// WithoutCAKey, which leaves the CA key out. Its Output and Passphrase
	// are set for each run.
	Backup CreateOptions
	Policy *policy.Engine
	// Notifier and Channel receive a message for every failed backup; no
	// Channel sends none.
	Notifier Notifier
	Channel  string
	Log      *slog.Logger

	// now is the clock, for tests.
	now func() time.Time
	// runTime overrides the time limit of one run, for tests.
	runTime time.Duration
}

// Scheduler takes a backup at every interval, uploads it and prunes the
// oldest ones. Run it on one hub of a cluster only: the leader.
type Scheduler struct {
	cfg ScheduleConfig
}

// NewScheduler returns a Scheduler for cfg.
func NewScheduler(cfg ScheduleConfig) *Scheduler {
	if cfg.Keep <= 0 {
		cfg.Keep = DefaultKeep
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.runTime <= 0 {
		cfg.runTime = min(cfg.Interval, maxRunTime)
	}
	return &Scheduler{cfg: cfg}
}

// Run takes backups until ctx is done. The first one is due an interval
// after the newest backup in the bucket, so a restart or a new leader does
// not take one early. A failed backup is logged, audited and notified, and
// tried again after the interval or an hour, whichever is shorter.
func (s *Scheduler) Run(ctx context.Context) error {
	delay := s.untilDue(ctx)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		delay = s.cfg.Interval
		if err := s.RunOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.report(ctx, err)
			delay = min(s.cfg.Interval, maxRetryAfter)
		}
		timer.Reset(delay)
	}
}

// untilDue is the time until the next backup is due, from the newest
// backup in the bucket. When the bucket cannot be read it is now: the
// backup will fail and say why.
func (s *Scheduler) untilDue(ctx context.Context) time.Duration {
	keys, err := s.scheduled(ctx)
	if err != nil || len(keys) == 0 {
		return 0
	}
	newest := strings.TrimSuffix(strings.TrimPrefix(keys[len(keys)-1], s.cfg.Prefix+"hearth-"), ".hbk")
	at, err := time.Parse(stampLayout, newest)
	if err != nil {
		return 0
	}
	return max(0, at.Add(s.cfg.Interval).Sub(s.cfg.now()))
}

// RunOnce takes one backup, uploads it and prunes the bucket, as the policy
// action hub.scheduled_backup. It fails once it takes longer than the
// interval or an hour, whichever is shorter.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.runTime)
	defer cancel()
	key := s.cfg.Prefix + "hearth-" + s.cfg.now().UTC().Format(stampLayout) + ".hbk"
	// The policy engine encodes Detail after fn returns: the size and the
	// count filled in below are audited with the outcome.
	detail := map[string]any{"bucket": s.cfg.BucketName, "key": key, "ca_key": !s.cfg.Backup.WithoutCAKey}
	return s.cfg.Policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   scheduleActor,
		Action:    policy.HubScheduledBackup,
		Target:    s.cfg.BucketName + "/" + key,
		Detail:    detail,
	}, func(ctx context.Context) error {
		size, err := s.upload(ctx, key)
		if err != nil {
			return err
		}
		detail["size"] = size
		pruned, err := s.prune(ctx)
		detail["pruned"] = pruned
		if err != nil {
			return fmt.Errorf("uploaded %s, then prune: %w", key, err)
		}
		s.cfg.Log.InfoContext(ctx, "scheduled backup uploaded", "bucket", s.cfg.BucketName, "key", key,
			"bytes", size, "pruned", pruned)
		return nil
	})
}

// upload writes the backup into a working directory of the data dir, which
// a crashed hub removes at its next start, and uploads it as key.
func (s *Scheduler) upload(ctx context.Context, key string) (int64, error) {
	dir, remove, err := store.NewTempDir(s.cfg.Backup.DataDir, store.BackupTempPrefix)
	if err != nil {
		return 0, fmt.Errorf("backup: %w", err)
	}
	defer remove()
	opts := s.cfg.Backup
	opts.Output = filepath.Join(dir, "backup.hbk")
	opts.Passphrase = s.cfg.Passphrase
	if _, err := Create(ctx, opts); err != nil {
		return 0, err
	}
	f, err := os.Open(opts.Output)
	if err != nil {
		return 0, fmt.Errorf("backup: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("backup: %w", err)
	}
	if err := s.cfg.Bucket.Put(ctx, key, f, info.Size()); err != nil {
		return 0, fmt.Errorf("upload: %w", err)
	}
	return info.Size(), nil
}

// scheduled returns the keys of the scheduled backups under the prefix,
// oldest first.
func (s *Scheduler) scheduled(ctx context.Context) ([]string, error) {
	keys, err := s.cfg.Bucket.List(ctx, s.cfg.Prefix)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	keys = slices.DeleteFunc(keys, func(k string) bool {
		return !scheduledName.MatchString(strings.TrimPrefix(k, s.cfg.Prefix))
	})
	slices.Sort(keys)
	return keys, nil
}

// prune deletes all but the newest Keep scheduled backups, and returns how
// many it deleted.
func (s *Scheduler) prune(ctx context.Context) (int, error) {
	keys, err := s.scheduled(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range keys[:max(0, len(keys)-s.cfg.Keep)] {
		if err := s.cfg.Bucket.Delete(ctx, k); err != nil {
			return n, fmt.Errorf("delete %s: %w", k, err)
		}
		n++
	}
	return n, nil
}

// report logs a failed backup and sends it to the notification channel.
// err never holds the passphrase or the bucket's credentials.
func (s *Scheduler) report(ctx context.Context, err error) {
	s.cfg.Log.ErrorContext(ctx, "scheduled backup failed", "bucket", s.cfg.BucketName, "err", err)
	if s.cfg.Channel == "" || s.cfg.Notifier == nil {
		return
	}
	msg := fmt.Sprintf("The scheduled backup to bucket %s failed: %v", s.cfg.BucketName, err)
	if nerr := s.cfg.Notifier.Send(ctx, s.cfg.Channel, "Hearth backup failed", msg); nerr != nil {
		s.cfg.Log.WarnContext(ctx, "could not notify the failed backup", "channel", s.cfg.Channel, "err", nerr)
	}
}
