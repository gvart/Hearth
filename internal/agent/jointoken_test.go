// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
)

// TestJoinWithAHubToken: a token naming its hub (an AP cluster master)
// enrolls there whatever hub URL is given, and through the given URL when
// the named hub cannot be reached.
func TestJoinWithAHubToken(t *testing.T) {
	h := startHub(t)
	const dead = "https://127.0.0.1:1"
	for name, urls := range map[string][2]string{
		"named hub":       {h.url, dead},
		"given hub after": {dead, h.url},
	} {
		t.Run(name, func(t *testing.T) {
			tok := h.token(t, time.Now().Add(15*time.Minute))
			id, err := agent.Join(t.Context(), urls[1], tok.EncodeHub(urls[0]), filepath.Join(t.TempDir(), "agent"), "pi")
			if err != nil {
				t.Fatalf("Join: %v", err)
			}
			if _, err := h.st.Devices().Get(t.Context(), id); err != nil {
				t.Fatalf("device not stored: %v", err)
			}
		})
	}
}
