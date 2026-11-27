// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"io"
	"runtime"
	"slices"
	"testing"
)

func TestServiceRunArgs(t *testing.T) {
	tests := []struct {
		dataDir      string
		localCeiling bool
		want         []string
	}{
		{`C:\ProgramData\Hearth\agent`, false, []string{"agent", "run", "--data-dir", `C:\ProgramData\Hearth\agent`}},
		{`D:\Hearth data\agent`, true, []string{"agent", "run", "--data-dir", `D:\Hearth data\agent`, "--local-ceiling"}},
	}
	for _, tt := range tests {
		got := serviceRunArgs(tt.dataDir, tt.localCeiling)
		if !slices.Equal(got, tt.want) {
			t.Errorf("serviceRunArgs(%q, %v) = %q, want %q", tt.dataDir, tt.localCeiling, got, tt.want)
		}
		// main tunes the agent on os.Args[1:3] == agent run.
		if got[0] != "agent" || got[1] != "run" {
			t.Errorf("serviceRunArgs(%q, %v) does not start with agent run", tt.dataDir, tt.localCeiling)
		}
	}
}

func TestHasLocalCeiling(t *testing.T) {
	tests := []struct {
		cmdline string
		want    bool
	}{
		{`"C:\Program Files\Hearth\hearth.exe" agent run --data-dir C:\ProgramData\Hearth\agent`, false},
		{`"C:\Program Files\Hearth\hearth.exe" agent run --data-dir C:\ProgramData\Hearth\agent --local-ceiling`, true},
		{`"C:\Program Files\Hearth\hearth.exe" agent run "--local-ceiling"`, true},
		{`hearth.exe agent run --local-ceiling=true`, true},
		{`hearth.exe agent run --data-dir C:\local-ceiling-not-a-flag`, false},
		{``, false},
	}
	for _, tt := range tests {
		if got := hasLocalCeiling(tt.cmdline); got != tt.want {
			t.Errorf("hasLocalCeiling(%q) = %v, want %v", tt.cmdline, got, tt.want)
		}
	}
}

func TestWindowsDataDir(t *testing.T) {
	tests := []struct {
		programData, role, want string
	}{
		{`C:\ProgramData`, "agent", `C:\ProgramData\Hearth\agent`},
		{`D:\ProgramData\`, "agent", `D:\ProgramData\Hearth\agent`},
		{``, "agent", `C:\ProgramData\Hearth\agent`},
		{`C:\ProgramData`, "hub", `C:\ProgramData\Hearth\hub`},
	}
	for _, tt := range tests {
		if got := windowsDataDir(tt.programData, tt.role); got != tt.want {
			t.Errorf("windowsDataDir(%q, %q) = %q, want %q", tt.programData, tt.role, got, tt.want)
		}
	}
}

func TestAgentServiceRefusedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the service commands work on Windows")
	}
	for _, args := range [][]string{{"agent", "service", "install"}, {"agent", "service", "uninstall"}} {
		cmd := newRootCmd(buildInfo{})
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); !errors.Is(err, errServiceUnsupported) {
			t.Errorf("%v: err = %v, want errServiceUnsupported", args, err)
		}
	}
}
