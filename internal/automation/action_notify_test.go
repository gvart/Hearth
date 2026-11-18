// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

type sent struct{ channel, title, message string }

// fakeNotifier has the channels in has, and fails sends with err.
type fakeNotifier struct {
	has []string
	err error

	mu   sync.Mutex
	sent []sent
}

func (f *fakeNotifier) Has(c string) bool {
	for _, h := range f.has {
		if h == c {
			return true
		}
	}
	return false
}

func (f *fakeNotifier) Send(_ context.Context, channel, title, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sent{channel, title, message})
	return f.err
}

const notifyYAML = `id: alert
triggers:
  - id: go
    type: manual
actions:
  - type: notify
    channel: phone
    title: "{{ .Trigger.ID }} fired"
    message: "from a {{ .Trigger.Type }} trigger"
`

func TestNotifyAction(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    string
		wantErr string
	}{
		{name: "sent", want: StatusSucceeded},
		{
			name: "send fails", err: errors.New("notify phone (ntfy): answered 403 Forbidden"), want: StatusFailed,
			wantErr: "answered 403 Forbidden",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &fakeNotifier{has: []string{"phone"}, err: tt.err}
			rec, audit := runOnce(t, notifyYAML, ActionDeps{Notifier: n})
			run := rec.all()[0]
			if run.Status != tt.want || !strings.Contains(run.Error, tt.wantErr) {
				t.Errorf("run = %s %q, want %s %q", run.Status, run.Error, tt.want, tt.wantErr)
			}
			if len(n.sent) != 1 || n.sent[0] != (sent{"phone", "go fired", "from a manual trigger"}) {
				t.Errorf("sent = %+v", n.sent)
			}
			e := audit.all()[0]
			if e.ActorID != "alert" || e.Action != string(policy.AutomationNotify) || e.Target != "phone" || e.Decision != policy.Allow {
				t.Errorf("audit entry = %+v", e)
			}
		})
	}
}

func TestNotifyLoadErrors(t *testing.T) {
	tests := []struct {
		name     string
		notifier Notifier
		action   string
		wantErr  string
	}{
		{
			"unknown channel", &fakeNotifier{has: []string{"phone"}}, "channel: pager\n    message: hi",
			`no notification channel "pager"`,
		},
		{"no channel", &fakeNotifier{}, "message: hi", "channel is required"},
		{"no message", &fakeNotifier{has: []string{"phone"}}, "channel: phone", "message is required"},
		{
			"unknown field", &fakeNotifier{has: []string{"phone"}}, "channel: phone\n    message: hi\n    url: https://x",
			`unknown field "url"`,
		},
		{
			"field the trigger lacks", &fakeNotifier{has: []string{"phone"}}, "channel: phone\n    message: \"{{ .Trigger.Device }}\"",
			".Trigger.Device: no such field",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: notify\n    " + tt.action + "\n"
			_, err := Parse("a.yaml", []byte(y), actionKinds(ActionDeps{Notifier: tt.notifier}))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestNotifyPlanWithoutNotifier checks a dry run, which knows no channels,
// accepts any channel name.
func TestNotifyPlanWithoutNotifier(t *testing.T) {
	a, err := Parse("a.yaml", []byte(notifyYAML), actionKinds(ActionDeps{}))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := Plan(&b, a); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `notify phone: "from a {{ .Trigger.Type }} trigger"`) || !strings.Contains(b.String(), "safe") {
		t.Errorf("plan = %s", b.String())
	}
}
