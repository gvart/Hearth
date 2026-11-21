// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/pki"
)

func TestBackupScheduler(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	passphrase := rand.Text()
	secret := rand.Text()
	passFile := write("passphrase", passphrase+"\n", 0o600)
	shortFile := write("short", "too short\n", 0o600)
	openFile := write("open", passphrase+"\n", 0o644)
	secretFile := write("secret", secret+"\n", 0o600)
	notifier, err := notify.Parse([]byte("channels: {phone: {type: ntfy, url: 'http://ntfy.lan', topic: t}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	valid := scheduledBackupOptions{
		interval: 24 * time.Hour, keep: 7, passphraseFile: passFile, endpoint: "http://minio.lan:9000",
		region: "us-east-1", bucket: "backups", prefix: "hearth", accessKeyID: "hearth", secretKeyFile: secretFile,
		notify: "phone",
	}
	with := func(change func(*scheduledBackupOptions)) scheduledBackupOptions {
		o := valid
		change(&o)
		return o
	}
	tests := []struct {
		name    string
		opts    scheduledBackupOptions
		on      bool
		wantErr string
	}{
		{"off", scheduledBackupOptions{keep: 7}, false, ""},
		{"on", valid, true, ""},
		{"secret from env", with(func(o *scheduledBackupOptions) { o.secretKeyFile, o.secretKey = "", secret }), true, ""},
		{"no notify channel", with(func(o *scheduledBackupOptions) { o.notify = "" }), true, ""},
		{"bucket without interval", with(func(o *scheduledBackupOptions) { o.interval = 0 }), false, "need --backup-interval"},
		{"negative interval", with(func(o *scheduledBackupOptions) { o.interval = -time.Hour }), false, "at least 5m"},
		{"interval under 5 minutes", with(func(o *scheduledBackupOptions) { o.interval = 4 * time.Minute }), false, "at least 5m"},
		{"interval of 5 minutes", with(func(o *scheduledBackupOptions) { o.interval = 5 * time.Minute }), true, ""},
		{"bad bucket name", with(func(o *scheduledBackupOptions) { o.bucket = "Hearth_Backups" }), false, "bucket"},
		{"keep zero", with(func(o *scheduledBackupOptions) { o.keep = 0 }), false, "--backup-keep"},
		{"no bucket", with(func(o *scheduledBackupOptions) { o.bucket = "" }), false, "--backup-s3-bucket"},
		{"no endpoint", with(func(o *scheduledBackupOptions) { o.endpoint = "" }), false, "--backup-s3-endpoint"},
		{"bad endpoint", with(func(o *scheduledBackupOptions) { o.endpoint = "minio.lan:9000" }), false, "--backup-s3-endpoint"},
		{"no passphrase file", with(func(o *scheduledBackupOptions) { o.passphraseFile = "" }), false, "--backup-passphrase-file"},
		{"missing passphrase file", with(func(o *scheduledBackupOptions) { o.passphraseFile = filepath.Join(dir, "nope") }), false, "--backup-passphrase-file"},
		{"short passphrase", with(func(o *scheduledBackupOptions) { o.passphraseFile = shortFile }), false, "at least 12"},
		{"no access key", with(func(o *scheduledBackupOptions) { o.accessKeyID = "" }), false, "--backup-s3-access-key-id"},
		{"no secret key", with(func(o *scheduledBackupOptions) { o.secretKeyFile = "" }), false, "HEARTH_BACKUP_S3_SECRET_ACCESS_KEY"},
		{"both secret keys", with(func(o *scheduledBackupOptions) { o.secretKey = secret }), false, "not both"},
		{"unknown channel", with(func(o *scheduledBackupOptions) { o.notify = "pager" }), false, "--backup-notify"},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name    string
			opts    scheduledBackupOptions
			on      bool
			wantErr string
		}{"world-readable passphrase file", with(func(o *scheduledBackupOptions) { o.passphraseFile = openFile }), false, "chmod 600"})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			got, err := backupScheduler(hubOptions{dataDir: dir, backup: tt.opts}, nil, nil, notifier, func() bool { return false }, nil,
				slog.New(slog.NewTextHandler(&logs, nil)))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if (got != nil) != tt.on {
				t.Fatalf("scheduler = %v, want on %v", got, tt.on)
			}
			for _, s := range []string{passphrase, secret} {
				if (err != nil && strings.Contains(err.Error(), s)) || strings.Contains(logs.String(), s) {
					t.Fatalf("a secret leaked: err %v, logs %s", err, logs.String())
				}
			}
		})
	}
}

// TestRestoreWithoutCAKey restores a scheduled backup made without
// --backup-include-ca: everything comes back but the CA key, the hub refuses
// to start until the key is there, and the key from a `hearth backup` file
// completes it.
func TestRestoreWithoutCAKey(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	dir, ca := initHub(t)
	st := openStore(t, dir)
	file := filepath.Join(t.TempDir(), "scheduled.hbk")
	if _, err := backup.Create(t.Context(), backup.CreateOptions{
		DataDir: dir, Store: st, Output: file, Passphrase: testBackupPassphrase, WithoutCAKey: true,
	}); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	out, err := execute(t, "restore", file, "--data-dir", target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "holds no CA key") || !strings.Contains(out, "enroll") {
		t.Errorf("restore output does not say what to do about the CA key:\n%s", out)
	}
	for name, want := range map[string]bool{dbFile: true, pki.CACertFile: true, pki.CAKeyFile: false} {
		if _, err := os.Stat(filepath.Join(target, name)); (err == nil) != want {
			t.Errorf("%s in the restored data dir: %v, want present %v", name, err, want)
		}
	}
	if _, err := pki.LoadOrCreateCA(target, time.Now()); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("hub CA without its key: %v, want refused as incomplete", err)
	}
	// As docs/backup.md says: the key of the hub's own data dir, as a
	// `hearth backup` file would restore it.
	if err := os.Link(filepath.Join(dir, pki.CAKeyFile), filepath.Join(target, pki.CAKeyFile)); err != nil {
		t.Fatal(err)
	}
	got, err := pki.LoadOrCreateCA(target, time.Now())
	if err != nil {
		t.Fatalf("CA with the key copied back: %v", err)
	}
	if got.Fingerprint() != ca.Fingerprint() {
		t.Fatal("the restored CA is not the hub's CA")
	}
}
