// SPDX-License-Identifier: AGPL-3.0-only

// Package policy classifies actions (read, safe, dangerous), makes allow/deny
// decisions and records every decision in the audit log. Nothing executes on a
// device without passing through this package.
package policy
