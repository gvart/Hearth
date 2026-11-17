// SPDX-License-Identifier: AGPL-3.0-only

package main

import "github.com/spf13/cobra"

func newRootCmd(info buildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:   "hearth",
		Short: "Hearth is a local-first control plane for your homelab",
		Long: "Hearth turns every device in your homelab into an entity you can see, control and automate.\n" +
			"One binary, two modes: run `hearth hub` on one node and `hearth agent` on the rest.",
		Version:       info.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.AddCommand(newVersionCmd(info), newHubCmd(), newTokenCmd(), newDeviceCmd(), newAgentCmd(), newAdminCmd(), newClusterCmd())
	return root
}
