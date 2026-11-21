// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

var errNoReauth = fmt.Errorf("the admin password was not entered again: %w", policy.ErrDenied)

// webActor is the web UI asking, with its re-authentication done or not.
func webActor(reauthed bool, called *int) CAActor {
	return CAActor{Kind: policy.ActorWeb, ID: "192.0.2.7", Precheck: func(context.Context) error {
		if called != nil {
			*called++
		}
		if !reauthed {
			return errNoReauth
		}
		return nil
	}}
}

// webCAAudit is st's audit entries of action by the web actor, as
// "decision: result".
func webCAAudit(t *testing.T, st *store.Store, action policy.Action) []string {
	t.Helper()
	entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(action)}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.ActorKind == policy.ActorWeb {
			out = append(out, e.Decision+": "+e.Result)
		}
	}
	return out
}

func hasEntry(entries []string, decision, result string) bool {
	for _, e := range entries {
		if strings.HasPrefix(e, decision+": ") && strings.Contains(e, result) {
			return true
		}
	}
	return false
}

// TestAPCARotationWebActor: the web UI's rotation steps go through the
// master's policy as web, after its re-authentication: denied without it,
// or by the policy, or on an isolated master; a step another master owns is
// refused naming the owner, as an audited denial; and the owner rotates and
// finishes.
func TestAPCARotationWebActor(t *testing.T) {
	ctx := t.Context()
	a, b, c := rotationTrio(t)

	// No re-authentication: denied, audited, nothing started.
	if _, err := a.node.ChangeCAAs(ctx, CARequest{Op: CAOpRotate}, webActor(false, nil)); !errors.Is(err, errNoReauth) {
		t.Fatalf("rotate without re-auth: %v, want the re-auth denial", err)
	}
	if a.ca.Next() != nil {
		t.Fatal("a denied rotation started")
	}
	if got := webCAAudit(t, a.st, policy.ClusterCARotate); !hasEntry(got, policy.Deny, "password was not entered again") {
		t.Fatalf("audit = %q, want the re-auth denial", got)
	}

	// The policy denies the web actor's dangerous actions.
	a.node.SetCAPolicy(policy.NewWithConfig(a.st.Audit(), a.st.Approvals(), policy.Config{
		Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}},
	}))
	if _, err := a.node.ChangeCAAs(ctx, CARequest{Op: CAOpRotate}, webActor(true, nil)); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("rotate denied by policy: %v, want denied", err)
	}
	// An isolated master refuses before anything else.
	isolated := policy.NewWithConfig(a.st.Audit(), a.st.Approvals(), policy.Config{})
	isolated.FailClosedWhen(func() bool { return true })
	a.node.SetCAPolicy(isolated)
	calls := 0
	_, err := a.node.ChangeCAAs(ctx, CARequest{Op: CAOpRotate}, webActor(true, &calls))
	if !errors.Is(err, policy.ErrDenied) || !strings.Contains(err.Error(), policy.ErrIsolated) || calls != 0 {
		t.Fatalf("rotate on an isolated master: %v (precheck called %d times), want the isolation denial", err, calls)
	}
	if a.ca.Next() != nil {
		t.Fatal("a denied rotation started")
	}
	prepareRotation(t, a)

	// Nothing to finish: refused, as an audited denial.
	_, err = a.node.ChangeCAAs(ctx, CARequest{Op: CAOpFinish}, webActor(true, nil))
	if !errors.Is(err, ErrNoRotation) || !errors.Is(err, policy.ErrDenied) || CAErrorKind(err) != "no_rotation" {
		t.Fatalf("finish with no rotation: %v, want ErrNoRotation", err)
	}
	if got := webCAAudit(t, a.st, policy.ClusterCAFinish); !hasEntry(got, policy.Deny, ErrNoRotation.Error()) {
		t.Fatalf("audit = %q, want the refusal", got)
	}

	// The web UI starts it on a, which owns it.
	if _, err := a.node.ChangeCAAs(ctx, CARequest{Op: CAOpRotate}, webActor(true, nil)); err != nil {
		t.Fatal(err)
	}
	if got := webCAAudit(t, a.st, policy.ClusterCARotate); !hasEntry(got, policy.Allow, "ok") {
		t.Fatalf("audit = %q, want the rotation", got)
	}
	waitUntil(t, 5*time.Second, "b to see the rotation", func() bool { return b.node.rotationActive() })

	// b may not finish or abort it while a is alive: it names a. The
	// re-authentication comes first.
	if _, err := b.node.ChangeCAAs(ctx, CARequest{Op: CAOpFinish}, webActor(false, nil)); !errors.Is(err, errNoReauth) ||
		errors.Is(err, ErrRotationOwner) {
		t.Fatalf("finish on b without re-auth: %v, want the re-auth denial", err)
	}
	for _, op := range []string{CAOpFinish, CAOpAbort} {
		_, err := b.node.ChangeCAAs(ctx, CARequest{Op: op}, webActor(true, nil))
		if !errors.Is(err, ErrRotationOwner) || CAErrorKind(err) != "rotation_owner" || !strings.Contains(err.Error(), "master a ") {
			t.Fatalf("%s on b: %v, want ErrRotationOwner naming a", op, err)
		}
		if strings.Contains(err.Error(), "by web/") {
			t.Errorf("%s on b: %q carries the denial's prefix", op, err)
		}
	}
	if got := webCAAudit(t, b.st, policy.ClusterCAFinish); !hasEntry(got, policy.Deny, "master a started it") {
		t.Fatalf("b's audit = %q, want the owner refusal", got)
	}
	if !a.node.rotationActive() {
		t.Fatal("a refused step moved the rotation")
	}

	waitUntil(t, 10*time.Second, "every member to hold the new CA", func() bool {
		return b.ca.HasNextKey() && b.node.nextCert.Load() != nil && c.node.nextCert.Load() != nil
	})
	if _, err := a.node.ChangeCAAs(ctx, CARequest{Op: CAOpFinish}, webActor(true, nil)); err != nil {
		t.Fatal(err)
	}
	if got := webCAAudit(t, a.st, policy.ClusterCAFinish); !hasEntry(got, policy.Allow, "ok") {
		t.Fatalf("audit = %q, want the finish", got)
	}
	// The CLI's refusals keep coming before policy, without the denial.
	if _, err := a.node.ChangeCA(ctx, CARequest{Op: CAOpAbort, Actor: "admin@test"}); !errors.Is(err, ErrNoRotation) ||
		errors.Is(err, policy.ErrDenied) {
		t.Fatalf("CLI abort with no rotation: %v, want ErrNoRotation alone", err)
	}
}
