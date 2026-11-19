// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// approvalTestPassword is the admin password the approval tests set.
const approvalTestPassword = "approver-pw-4b7f"

func writePolicy(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, policy.ConfigFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A revocation the policy file says to confirm waits for `hearth approval
// approve`, then runs.
func TestApprovalFlow(t *testing.T) {
	dir, _ := initHub(t)
	writePolicy(t, dir, "classes: {dangerous: confirm}\n")
	if out, err := executeWithStdin(t, approvalTestPassword+"\n", "admin", "set-password", "--data-dir", dir); err != nil {
		t.Fatalf("set-password = %v\n%s", err, out)
	}
	st := openStore(t, dir)
	if err := st.Devices().Upsert(t.Context(), store.Device{ID: "pi", Status: store.StatusUnknown}); err != nil {
		t.Fatal(err)
	}
	if err := st.Certs().Create(t.Context(), "0a", "pi"); err != nil {
		t.Fatal(err)
	}

	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := execute(t, "device", "revoke", "pi", "--data-dir", dir)
		done <- result{out, err}
	}()
	var id string
	deadline := time.Now().Add(5 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		aps, err := st.Approvals().List(t.Context(), store.ApprovalPending, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(aps) == 1 {
			id = aps[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("the revocation was not held for approval")
	}
	out, err := execute(t, "approval", "list", "--data-dir", dir)
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, "device.revoke") {
		t.Fatalf("approval list = %v\n%s", err, out)
	}
	// Approving needs the admin password, on stdin here; a missing or wrong
	// one leaves the approval pending.
	for _, stdin := range []string{"", "\n", "wrong-password-9d2e\n"} {
		out, err := executeWithStdin(t, stdin, "approval", "approve", id, "--data-dir", dir)
		if err == nil || !strings.Contains(err.Error(), "re-authenticat") {
			t.Fatalf("approve with stdin %q = %v\n%s", stdin, err, out)
		}
		if strings.Contains(out+err.Error(), "wrong-password-9d2e") {
			t.Errorf("the password was echoed: %s %v", out, err)
		}
		if ap, err := st.Approvals().Get(t.Context(), id); err != nil || ap.Status != store.ApprovalPending {
			t.Fatalf("approval after a refused approve = %+v, %v", ap, err)
		}
	}
	if out, err := executeWithStdin(t, approvalTestPassword+"\n", "approval", "approve", id, "--data-dir", dir); err != nil || !strings.Contains(out, "Approved "+id) {
		t.Fatalf("approve = %v\n%s", err, out)
	}
	r := <-done
	if r.err != nil || !strings.Contains(r.out, "needs approval") || !strings.Contains(r.out, "Revoked 1 certificate") {
		t.Fatalf("revoke = %v\n%s", r.err, r.out)
	}
	if _, err := execute(t, "approval", "deny", id, "--data-dir", dir); err == nil {
		t.Error("denying a decided approval succeeded")
	}
	if _, err := execute(t, "approval", "approve", "nope", "--data-dir", dir); err == nil || !strings.Contains(err.Error(), "no approval nope") {
		t.Errorf("approve unknown = %v", err)
	}
	out, err = execute(t, "approval", "list", "--all", "--data-dir", dir)
	if err != nil || !strings.Contains(out, "approved by admin/") {
		t.Errorf("approval list --all = %v\n%s", err, out)
	}
}

func TestCLIDryRun(t *testing.T) {
	dir, _ := initHub(t)
	out, err := execute(t, "token", "create", "--data-dir", dir, "--dry-run")
	if err != nil || !strings.Contains(out, "Dry run: token.create would be allowed") || strings.Contains(out, "HEARTH_TOKEN") {
		t.Fatalf("token create --dry-run = %v\n%s", err, out)
	}
	writePolicy(t, dir, "classes: {safe: confirm, dangerous: deny}\n")
	out, err = execute(t, "token", "create", "--data-dir", dir, "--dry-run")
	if err != nil || !strings.Contains(out, "would be held for approval") {
		t.Fatalf("token create --dry-run, confirm = %v\n%s", err, out)
	}
	if _, err := execute(t, "device", "revoke", "pi", "--data-dir", dir, "--dry-run"); err == nil ||
		!strings.Contains(err.Error(), "denied by the policy configuration") {
		t.Fatalf("device revoke --dry-run, deny = %v", err)
	}
	st := openStore(t, dir)
	entries, err := st.Audit().List(t.Context(), 10)
	if err != nil || len(entries) != 3 {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Result, policy.DryRun) {
			t.Errorf("audit entry %+v is not a dry run", e)
		}
	}
	if aps, _ := st.Approvals().List(t.Context(), "", 10); len(aps) != 0 {
		t.Error("a dry run held an approval")
	}

	writePolicy(t, dir, "classes: {safe: maybe}\n")
	if _, err := execute(t, "token", "create", "--data-dir", dir); err == nil || !strings.Contains(err.Error(), "unknown mode") {
		t.Errorf("invalid policy file = %v", err)
	}
}
