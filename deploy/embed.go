// SPDX-License-Identifier: AGPL-3.0-only

// Package deploy embeds the agent installer so the hub can serve it at
// /install.sh. It lives here because //go:embed cannot reach parent dirs.
package deploy

import _ "embed"

// InstallScript is deploy/install.sh.
//
//go:embed install.sh
var InstallScript []byte
