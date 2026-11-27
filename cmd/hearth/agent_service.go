// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/agent"
)

// errServiceUnsupported is `hearth agent service` anywhere but Windows.
var errServiceUnsupported = errors.New("`hearth agent service` manages the agent's Windows service; " +
	"on Linux and macOS, deploy/install.sh installs the agent as a systemd or launchd service")

func newAgentServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Install or remove the agent's Windows service",
		Long: "Install or remove " + agent.ServiceName + ", the Windows service that runs `hearth agent run`\n" +
			"as LocalSystem from this binary, started at boot. deploy/install.ps1 runs these; Linux and macOS\n" +
			"use deploy/install.sh instead. Run them from an elevated (Administrator) shell.",
	}
	cmd.AddCommand(newAgentServiceInstallCmd(), newAgentServiceUninstallCmd())
	return cmd
}

func newAgentServiceInstallCmd() *cobra.Command {
	var (
		dataDir      string
		localCeiling bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the agent as a Windows service",
		Long: "Register " + agent.ServiceName + ": started automatically at boot, restarted after a crash, logging\n" +
			"to the Windows event log (Application, source " + agent.ServiceName + "). It creates the data dir,\n" +
			"readable only by SYSTEM and Administrators, so run it before `hearth agent join`. It does not\n" +
			"start the service: Start-Service " + agent.ServiceName + " does, once the device is enrolled.\n\n" +
			"A service already registered keeps its command line, and any --allow-* flags added to it\n" +
			"(sc.exe config); uninstall it first to change them.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return installAgentService(cmd.OutOrStdout(), dataDir, localCeiling)
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("agent"), "agent data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&localCeiling, "local-ceiling", false,
		"run the agent with --local-ceiling: the hub may not change what it can do here")
	return cmd
}

func newAgentServiceUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the agent's Windows service",
		Long:  "Stop and remove " + agent.ServiceName + ". The data dir, the device's identity, is kept.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return uninstallAgentService(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

// serviceRunArgs are the arguments the service runs this binary with. They
// start with `agent run`, which main checks for to tune the agent.
func serviceRunArgs(dataDir string, localCeiling bool) []string {
	args := []string{"agent", "run", "--data-dir", dataDir}
	if localCeiling {
		args = append(args, "--local-ceiling")
	}
	return args
}

// hasLocalCeiling reports whether a service's command line runs the agent
// with --local-ceiling.
func hasLocalCeiling(cmdline string) bool {
	return slices.ContainsFunc(strings.Fields(cmdline), func(f string) bool {
		f = strings.Trim(f, `"`)
		return f == "--local-ceiling" || strings.HasPrefix(f, "--local-ceiling=")
	})
}

// windowsDataDir is the data dir of role on Windows: under %ProgramData%
// (programData), or C:\ProgramData if that is not set.
func windowsDataDir(programData, role string) string {
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return strings.TrimRight(programData, `\`) + `\Hearth\` + role
}

// programDataDir is windowsDataDir from the environment.
func programDataDir(role string) string { return windowsDataDir(os.Getenv("ProgramData"), role) }
