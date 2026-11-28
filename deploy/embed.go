// SPDX-License-Identifier: AGPL-3.0-only

// Package deploy embeds the agent installers so the hub can serve them at
// /install.sh and /install.ps1. It lives here because //go:embed cannot reach parent dirs.
package deploy

import _ "embed"

// InstallScript is deploy/install.sh.
//
//go:embed install.sh
var InstallScript []byte

// InstallPowerShell is deploy/install.ps1, the Windows installer.
//
//go:embed install.ps1
var InstallPowerShell []byte
