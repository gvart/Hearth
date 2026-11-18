// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestNotifyApprovals(t *testing.T) {
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	n, err := notify.Parse([]byte("channels:\n  phone:\n    type: ntfy\n    url: http://ntfy.lan\n    topic: lab\n"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	pol := policy.New(st.Audit())
	if err := notifyApprovals(pol, policy.ApprovalNotify{}, st, n, "hub", "", log); err != nil {
		t.Errorf("no channel: %v", err)
	}
	if err := notifyApprovals(pol, policy.ApprovalNotify{Channel: "phone"}, st, n, "hub", "", log); err != nil {
		t.Errorf("known channel: %v", err)
	}
	err = notifyApprovals(pol, policy.ApprovalNotify{Channel: "pager"}, st, n, "hub", "", log)
	if err == nil || !strings.Contains(err.Error(), `"pager"`) {
		t.Errorf("unknown channel = %v, want an error naming it", err)
	}
	if err := notifyApprovals(pol, policy.ApprovalNotify{Channel: "phone"}, st, &notify.Notifier{}, "hub", "", log); err == nil {
		t.Error("channel without a channels file: no error")
	}
}
