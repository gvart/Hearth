// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package hub

import (
	"net/http"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// TestAutomationPipeDoesNotHang: reading a named pipe would block for ever.
func TestAutomationPipeDoesNotHang(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	if err := syscall.Mkfifo(filepath.Join(f.dir, "pipe.yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan apiResp, 1)
	go func() { done <- f.do(t, http.MethodGet, "/api/v1/automations", "", f.cookie) }()
	select {
	case resp := <-done:
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d: %s", resp.StatusCode, resp.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listing the directory hangs on a named pipe")
	}
}
