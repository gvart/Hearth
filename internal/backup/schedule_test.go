// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// memBucket is a Bucket in memory.
type memBucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	calls   int
	putErr  error
	listErr error
	// put is signalled after every successful Put.
	put chan string
}

func newMemBucket(keys ...string) *memBucket {
	b := &memBucket{objects: map[string][]byte{}, put: make(chan string, 16)}
	for _, k := range keys {
		b.objects[k] = []byte("old")
	}
	return b
}

func (b *memBucket) Put(_ context.Context, key string, body io.ReadSeeker, size int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.putErr != nil {
		return b.putErr
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return errors.New("size does not match the body")
	}
	b.objects[key] = data
	b.put <- key
	return nil
}

func (b *memBucket) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.listErr != nil {
		return nil, b.listErr
	}
	var out []string
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (b *memBucket) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	delete(b.objects, key)
	return nil
}

func (b *memBucket) keys() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Sorted(maps.Keys(b.objects))
}

func (b *memBucket) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// sentMessage is one notification.
type sentMessage struct{ channel, title, message string }

type fakeNotifier struct{ sent chan sentMessage }

func (n *fakeNotifier) Send(_ context.Context, channel, title, message string) error {
	n.sent <- sentMessage{channel, title, message}
	return nil
}

func newScheduler(t *testing.T, b Bucket, n Notifier, now time.Time) (*Scheduler, string, *store.Store) {
	t.Helper()
	dir, st := newHub(t)
	s := NewScheduler(ScheduleConfig{
		Interval: time.Hour, Keep: 3, Bucket: b, BucketName: "backups", Prefix: "hearth/",
		Passphrase: testPassphrase,
		// As the hub does by default.
		Backup: CreateOptions{DataDir: dir, Store: st, HearthVersion: "test", WithoutCAKey: true, kdf: testKDF},
		Policy: policy.New(st.Audit()), Notifier: n, Channel: "phone",
		Log: slog.New(slog.DiscardHandler), now: func() time.Time { return now },
	})
	return s, dir, st
}

func TestRunOnceUploadsAndPrunes(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	untouched := []string{
		"hearth/notes.txt", "hearth/sub/hearth-20200101T000000Z.hbk", "other/hearth-20200101T000000Z.hbk",
		"hearth/hearth-2020.hbk",
	}
	b := newMemBucket(append([]string{
		"hearth/hearth-20261113T120000Z.hbk", "hearth/hearth-20261114T120000Z.hbk",
		"hearth/hearth-20261115T120000Z.hbk", "hearth/hearth-20261118T120000Z.hbk",
	}, untouched...)...)
	s, _, st := newScheduler(t, b, nil, now)
	if err := s.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := append([]string{
		"hearth/hearth-20261115T120000Z.hbk", "hearth/hearth-20261118T120000Z.hbk", "hearth/hearth-20261119T120000Z.hbk",
	}, untouched...)
	slices.Sort(want)
	if got := b.keys(); !slices.Equal(got, want) {
		t.Fatalf("bucket holds %q\nwant %q", got, want)
	}

	// The audit log shows the backup and its outcome, and no secret.
	entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.HubScheduledBackup)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Result != "ok" || entries[0].ActorKind != policy.ActorHub ||
		entries[0].Target != "backups/hearth/hearth-20261119T120000Z.hbk" {
		t.Fatalf("audit = %+v", entries)
	}
	if d := string(entries[0].Detail); !strings.Contains(d, `"pruned":2`) || !strings.Contains(d, `"size":`) ||
		strings.Contains(d, testPassphrase) {
		t.Fatalf("audit detail = %s", d)
	}

	// What was uploaded restores with the passphrase, like any backup.
	file := filepath.Join(t.TempDir(), "downloaded.hbk")
	if err := os.WriteFile(file, b.objects["hearth/hearth-20261119T120000Z.hbk"], 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(t.Context(), RestoreOptions{Input: file, Passphrase: testPassphrase, DataDir: target}); err != nil {
		t.Fatalf("restore the uploaded backup: %v", err)
	}
	rs, err := store.Open(t.Context(), filepath.Join(target, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	if _, err := rs.Devices().Get(t.Context(), "dev-1"); err != nil {
		t.Fatalf("restored hub lost its device: %v", err)
	}
}

func TestRunOnceLeavesNoLocalCopy(t *testing.T) {
	b := newMemBucket()
	s, dir, _ := newScheduler(t, b, nil, time.Now())
	b.putErr = errors.New("bucket unreachable")
	if err := s.RunOnce(t.Context()); err == nil {
		t.Fatal("RunOnce succeeded with a failing bucket")
	}
	if err := s.RunOnce(t.Context()); err == nil {
		t.Fatal("RunOnce succeeded with a failing bucket")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), store.BackupTempPrefix) || strings.HasSuffix(e.Name(), ".hbk") {
			t.Fatalf("left behind in the data dir: %s", e.Name())
		}
	}
}

func TestFailedBackupIsReported(t *testing.T) {
	secret := rand.Text()
	for _, tc := range []struct {
		name string
		fail func(*memBucket)
		want string
	}{
		{"upload refused", func(b *memBucket) {
			b.putErr = errors.New("s3 request failed: PUT: HTTP 403 AccessDenied")
		}, "403 AccessDenied"},
		{"bucket unreachable", func(b *memBucket) {
			b.listErr = errors.New("dial tcp 192.0.2.1:9000: connect: connection refused")
			b.putErr = b.listErr
		}, "connection refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newMemBucket()
			tc.fail(b)
			n := &fakeNotifier{sent: make(chan sentMessage, 4)}
			s, _, st := newScheduler(t, b, n, time.Now())
			s.cfg.Passphrase = testPassphrase + secret
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx) }()
			var m sentMessage
			select {
			case m = <-n.sent:
			case <-time.After(10 * time.Second):
				t.Fatal("no notification of the failed backup")
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if m.channel != "phone" || !strings.Contains(m.message, tc.want) || strings.Contains(m.message, secret) {
				t.Fatalf("notification = %+v", m)
			}
			entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.HubScheduledBackup)}}, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || !strings.HasPrefix(entries[0].Result, "error: ") || !strings.Contains(entries[0].Result, tc.want) {
				t.Fatalf("audit = %+v", entries)
			}
		})
	}
}

// stallingBucket accepts an upload and never answers, like a server that
// stopped responding after the connection opened.
type stallingBucket struct{ *memBucket }

func (stallingBucket) Put(ctx context.Context, _ string, _ io.ReadSeeker, _ int64) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestStalledUploadFailsAndIsReported(t *testing.T) {
	n := &fakeNotifier{sent: make(chan sentMessage, 4)}
	s, _, st := newScheduler(t, stallingBucket{newMemBucket()}, n, time.Now())
	s.cfg.runTime = 500 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case m := <-n.sent:
		if !strings.Contains(m.message, "deadline exceeded") {
			t.Errorf("notification = %+v, want the time limit", m)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled upload was never reported")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.HubScheduledBackup)}}, 10)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Result, "error: ") {
		t.Fatalf("audit = %+v, %v, want the failure", entries, err)
	}
}

func TestStopDoesNotNotify(t *testing.T) {
	b := newMemBucket("hearth/hearth-" + time.Now().UTC().Format(stampLayout) + ".hbk")
	n := &fakeNotifier{sent: make(chan sentMessage, 1)}
	s, _, _ := newScheduler(t, b, n, time.Now())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if len(n.sent) != 0 {
		t.Fatal("a stop was notified as a failure")
	}
}

func TestUntilDue(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		keys []string
		list error
		want time.Duration
	}{
		{"empty bucket", nil, nil, 0},
		{"newest 20 minutes ago", []string{"hearth/hearth-20261118T120000Z.hbk", "hearth/hearth-20261119T114000Z.hbk"}, nil, 40 * time.Minute},
		{"overdue", []string{"hearth/hearth-20261119T090000Z.hbk"}, nil, 0},
		{"other objects only", []string{"hearth/hearth-x.hbk", "hearth/notes.txt"}, nil, 0},
		{"unreadable bucket", nil, errors.New("refused"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newMemBucket(tc.keys...)
			b.listErr = tc.list
			s, _, _ := newScheduler(t, b, nil, now)
			if got := s.untilDue(t.Context()); got != tc.want {
				t.Fatalf("untilDue = %v, want %v", got, tc.want)
			}
		})
	}
}

// fakeLeader is a cluster node whose leadership the test sets.
type fakeLeader struct{ leading atomic.Bool }

func (n *fakeLeader) IsLeader() bool                  { return n.leading.Load() }
func (n *fakeLeader) WaitReady(context.Context) error { return nil }

func TestOnlyTheLeaderBacksUp(t *testing.T) {
	b := newMemBucket()
	s, _, _ := newScheduler(t, b, nil, time.Now())
	node := &fakeLeader{}
	changed := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- automation.RunWhileLeading(ctx, node, changed, slog.New(slog.DiscardHandler), s.Run)
	}()
	changed <- struct{}{} // leadership changed, still not this hub
	select {
	case k := <-b.put:
		t.Fatalf("a follower uploaded %s", k)
	case <-time.After(300 * time.Millisecond):
	}
	if n := b.callCount(); n != 0 {
		t.Fatalf("a follower called the bucket %d times", n)
	}
	node.leading.Store(true)
	changed <- struct{}{}
	select {
	case <-b.put:
	case <-time.After(10 * time.Second):
		t.Fatal("the leader took no backup")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestScheduledNameIsExact(t *testing.T) {
	for name, want := range map[string]bool{
		"hearth-20261119T120000Z.hbk":     true,
		"hearth-20261119T120000Z.hbk.bak": false,
		"x/hearth-20261119T120000Z.hbk":   false,
		"hearth-20261119T1200Z.hbk":       false,
		"mine-20261119T120000Z.hbk":       false,
	} {
		if got := scheduledName.MatchString(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}
