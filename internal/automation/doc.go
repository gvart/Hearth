// SPDX-License-Identifier: AGPL-3.0-only

// Package automation loads automations from YAML files and runs them.
//
// An automation is one file: triggers start a run, conditions decide whether
// it goes on, and actions execute in order. Every action passes through
// internal/policy, with the automation as the actor, and each decision is in
// the audit log. Each automation has a concurrency mode for a trigger that
// fires while a run is in progress: single (drop it), queued (run it after)
// or restart (cancel the current run and start again).
//
// The runtime reloads the directory when its files change. In a cluster it
// runs on the one master that owns it (see RunWhileLeading). Finished runs
// are recorded in the store's run history.
package automation
