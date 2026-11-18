// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"testing"
	"time"
)

func TestScheduleTrigger(t *testing.T) {
	// 2026-03-02 02:59:30 UTC, a Monday.
	start := time.Date(2026, 3, 2, 2, 59, 30, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		cron  string
		waits []time.Duration // until each of the next firings
	}{
		{"daily at 3", "CRON_TZ=UTC 0 3 * * *", []time.Duration{30 * time.Second, 24 * time.Hour}},
		{"every 15 min", "CRON_TZ=UTC */15 * * * *", []time.Duration{30 * time.Second, 15 * time.Minute, 15 * time.Minute}},
		{"weekdays at 9", "CRON_TZ=UTC 0 9 * * 1-5", []time.Duration{6*time.Hour + 30*time.Second, 24 * time.Hour}},
		{"descriptor", "@every 1h", []time.Duration{time.Hour, time.Hour}},
		{"zone", "CRON_TZ=Europe/Chisinau 0 6 * * *", []time.Duration{time.Hour + 30*time.Second}}, // 06:00 EET is 04:00 UTC
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock(start)
			w := watch(t, mustBuildTrigger(t, TriggerDeps{Clock: clock}, "type: schedule\ncron: '"+tc.cron+"'"))
			for i, want := range tc.waits {
				d := clock.waitForWaiter(t)
				if d != want {
					t.Fatalf("firing %d: waits %s, want %s", i+1, d, want)
				}
				clock.Advance(d - time.Second)
				if n := w.fires.Load(); n != int32(i) {
					t.Fatalf("fired early: fires = %d, want %d", n, i)
				}
				clock.Advance(time.Second)
				clock.waitForWaiter(t) // fired, and waiting for the next one
				if n := w.fires.Load(); n != int32(i+1) {
					t.Fatalf("fires = %d, want %d", n, i+1)
				}
			}
		})
	}
}

func TestScheduleTriggerInvalid(t *testing.T) {
	for _, src := range []string{
		"type: schedule",
		"type: schedule\ncron: '61 * * * *'",
		"type: schedule\ncron: '* * * *'",
		"type: schedule\ncron: 'CRON_TZ=Nowhere/City 0 3 * * *'",
	} {
		_, err := buildTrigger(t, TriggerDeps{}, src)
		wantErrContains(t, err, "cron")
	}
}

func TestScheduleTriggerDescribe(t *testing.T) {
	tr := mustBuildTrigger(t, TriggerDeps{}, "type: schedule\ncron: '0 3 * * *'")
	if got, want := tr.Describe(), `fires on schedule "0 3 * * *"`; got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
}
