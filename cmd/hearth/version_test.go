// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	info := buildInfo{
		Version:   "v1.2.3",
		Commit:    "abc1234",
		Date:      "2026-11-17T12:00:00Z",
		GoVersion: "go1.26.0",
		Platform:  "linux/arm64",
	}

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "version subcommand",
			args: []string{"version"},
			want: []string{"hearth v1.2.3", "abc1234", "2026-11-17T12:00:00Z", "go1.26.0", "linux/arm64"},
		},
		{
			name: "version flag",
			args: []string{"--version"},
			want: []string{"hearth v1.2.3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			cmd := newRootCmd(info)
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tt.args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("execute %v: %v", tt.args, err)
			}
			for _, w := range tt.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output %q does not contain %q", out.String(), w)
				}
			}
		})
	}
}

func TestVersionCommandRejectsArgs(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd(buildInfo{Version: "dev"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"version", "extra"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for unexpected argument, got nil")
	}
}

func TestMergeVCS(t *testing.T) {
	t.Parallel()

	settings := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "deadbeef"},
		{Key: "vcs.time", Value: "2026-01-02T03:04:05Z"},
		{Key: "vcs.modified", Value: "true"},
	}

	tests := []struct {
		name string
		in   buildInfo
		want buildInfo
	}{
		{
			name: "ldflags win over vcs",
			in:   buildInfo{Version: "v1.0.0", Commit: "cafe", Date: "2026-11-17"},
			want: buildInfo{Version: "v1.0.0", Commit: "cafe", Date: "2026-11-17"},
		},
		{
			name: "dev build falls back to vcs and marks dirty",
			in:   buildInfo{Version: "dev"},
			want: buildInfo{Version: "dev", Commit: "deadbeef-dirty", Date: "2026-01-02T03:04:05Z"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := mergeVCS(tt.in, settings); got != tt.want {
				t.Errorf("mergeVCS() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResolveBuildInfoDefaults(t *testing.T) {
	t.Parallel()

	info := resolveBuildInfo("", "", "")
	if info.Version != "dev" {
		t.Errorf("Version = %q, want dev", info.Version)
	}
	if info.Commit == "" || info.Date == "" || info.GoVersion == "" || info.Platform == "" {
		t.Errorf("expected all fields populated, got %+v", info)
	}
}
