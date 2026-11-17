// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

const unknown = "unknown"

// buildInfo describes the running binary.
type buildInfo struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
	Platform  string
}

// resolveBuildInfo combines link-time values with what the Go toolchain embedded
// in the binary, so builds without ldflags (`go build` in a checkout, or
// `go install ...@vX.Y.Z`) still report something useful.
func resolveBuildInfo(version, commit, date string) buildInfo {
	info := buildInfo{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info = mergeModuleVersion(info, bi.Main.Version)
		info = mergeVCS(info, bi.Settings)
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = unknown
	}
	if info.Date == "" {
		info.Date = unknown
	}
	return info
}

// mergeModuleVersion uses the module version recorded by `go install ...@vX.Y.Z`
// (module-cache builds carry no vcs.* settings) when no version was linked in.
func mergeModuleVersion(info buildInfo, moduleVersion string) buildInfo {
	if (info.Version == "" || info.Version == "dev") && moduleVersion != "" && moduleVersion != "(devel)" {
		info.Version = moduleVersion
	}
	return info
}

func mergeVCS(info buildInfo, settings []debug.BuildSetting) buildInfo {
	dirty := false
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if dirty && info.Commit != "" && info.Version == "dev" {
		info.Commit += "-dirty"
	}
	return info
}

func newVersionCmd(info buildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeVersion(cmd.OutOrStdout(), info)
		},
	}
}

func writeVersion(w io.Writer, info buildInfo) error {
	_, err := fmt.Fprintf(w, "hearth %s\n  commit:   %s\n  built:    %s\n  go:       %s\n  platform: %s\n",
		info.Version, info.Commit, info.Date, info.GoVersion, info.Platform)
	if err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	return nil
}
