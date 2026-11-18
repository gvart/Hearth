// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package agent_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
)

// TestShellOverStream opens a shell on a real agent through the hub: only
// on an agent started with --allow-shell.
func TestShellOverStream(t *testing.T) {
	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	startAgentWith(t, agent.Config{DataDir: dataDir, Ceiling: agent.Ceiling{Shell: true}})
	var sh *hub.Shell
	var err error
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		sh, err = h.agents.OpenShell(t.Context(), id, 24, 80)
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if err != nil {
		t.Fatalf("OpenShell = %v", err)
	}
	if err := sh.Write([]byte("echo over-$((40+2))\n")); err != nil {
		t.Fatal(err)
	}
	var out []byte
	for !bytes.Contains(out, []byte("over-42")) {
		b, err := sh.Read(t.Context())
		if err != nil {
			t.Fatalf("read: %v (output %q)", err, out)
		}
		out = append(out, b...)
	}
	sh.Close()
	for {
		if _, err := sh.Read(t.Context()); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if ex := sh.Exit(); ex.GetError() != "session closed" {
		t.Errorf("exit = %v, want session closed", ex)
	}

	// Without --allow-shell the hub refuses before asking.
	h2 := startRestartableHub(t, time.Second)
	id2, dataDir2 := h2.join(t)
	startAgentWith(t, agent.Config{DataDir: dataDir2, Ceiling: agent.Ceiling{Exec: []string{"/bin/sh"}}})
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		_, err = h2.agents.OpenShell(t.Context(), id2, 24, 80)
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Fatalf("shell without --allow-shell = %v, want beyond the ceiling", err)
	}
}
