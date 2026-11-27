// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestReleaseMirrorFlag checks that --release-mirror wins over
// HEARTH_RELEASE_MIRROR, which wins over no mirror.
func TestReleaseMirrorFlag(t *testing.T) {
	for _, tc := range []struct {
		name, env string
		args      []string
		want      string
	}{
		{"none", "", nil, ""},
		{"env", "https://env.lan/r", nil, "https://env.lan/r"},
		{"flag", "", []string{"--release-mirror", "https://flag.lan/r"}, "https://flag.lan/r"},
		{"flag over env", "https://env.lan/r", []string{"--release-mirror=https://flag.lan/r"}, "https://flag.lan/r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(releaseMirrorEnv, tc.env)
			cmd := newAgentRunCmd()
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			if got, _ := cmd.Flags().GetString("release-mirror"); got != tc.want {
				t.Errorf("release mirror = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReleaseMirrorRefused checks that a bad mirror URL stops the agent and
// the mirror command before they do anything.
func TestReleaseMirrorRefused(t *testing.T) {
	t.Setenv(releaseMirrorEnv, "")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"agent, not http", []string{"agent", "run", "--data-dir", t.TempDir(), "--release-mirror", "ftp://m.lan/r"}, "--release-mirror"},
		{"agent, credentials", []string{"agent", "run", "--data-dir", t.TempDir(), "--release-mirror", "https://u:p@m.lan/r"}, "credentials"},
		{"mirror, not a tag", []string{"release", "mirror", "latest", t.TempDir(), "--from", "http://127.0.0.1:1"}, "not a release tag"},
		{"mirror, bad --from", []string{"release", "mirror", "v1.2.3", t.TempDir(), "--from", "file:///srv"}, "--from"},
		{"mirror, one argument", []string{"release", "mirror", "v1.2.3"}, "accepts 2 arg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd(buildInfo{Version: "v1.0.0"})
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(tc.args)
			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v = %v, want an error with %q", tc.args, err, tc.want)
			}
			if strings.Contains(err.Error(), "u:p") {
				t.Errorf("error quotes the credentials: %v", err)
			}
		})
	}
}
