// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"fmt"
	"strings"
)

// MaxRunbookNotes bounds the operator's notes on a recorded session.
const MaxRunbookNotes = 2000

// RunbookChecks are the check types a runbook's check step may use, with
// their fields as the model is told them.
var RunbookChecks = []StepRef{
	{Type: "http", Does: "an HTTP GET succeeds", Fields: []FieldRef{
		{"url", "required: the URL to get"},
		{"status", "the status to expect, a number; default any 2xx or 3xx"},
		{"from", "a device whose agent runs the check instead of the hub"},
		{"timeout", "a duration: per attempt (default 5s)"},
	}},
	{Type: "tcp", Does: "a TCP port accepts connections", Fields: []FieldRef{
		{"address", "required: host:port"},
		{"from", "a device whose agent runs the check instead of the hub"},
		{"timeout", "a duration: per attempt (default 5s)"},
	}},
	{Type: "dns", Does: "a DNS server resolves a name", Fields: []FieldRef{
		{"name", "required: the name to resolve"},
		{"server", "required: the DNS server to ask, host or host:port"},
		{"from", "a device whose agent runs the check instead of the hub"},
		{"timeout", "a duration: per attempt (default 5s)"},
	}},
	{Type: "kube_node", Does: "a Kubernetes node is Ready", Fields: []FieldRef{
		{"cluster", "required: the cluster's name, as listed"},
		{"node", "required: the node's name"},
	}},
	{Type: "talos_node", Does: "a Talos node answers, optionally runs a version and is healthy", Fields: []FieldRef{
		{"node", "required: the node's address or hostname"},
		{"version", "a Talos version tag, such as v1.12.8"},
		{"healthy", "true: every service must be healthy"},
	}},
}

// RunbookExample is the example runbook the model is shown; a test parses
// it with the hub's step types.
const RunbookExample = `id: add-docker-host
description: Install Docker on pi5 and check that it runs, as done by hand in a terminal.
vars:
  device: pi5
steps:
  - id: go-ahead
    type: prompt
    prompt: confirm
    message: Install Docker on pi5 now?
  - id: update
    type: action
    description: Refresh the package lists.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/apt-get, update]
      timeout: 5m
  - id: install
    type: action
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/apt-get, install, -y, docker.io]
      timeout: 10m
    rollback:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/apt-get, remove, -y, docker.io]
      timeout: 10m
  - id: settle
    type: wait
    duration: 10s
  - id: running
    type: action
    description: The service is active.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/systemctl, is-active, docker]
`

// runbookSystem is the fixed part of the system prompt of a runbook draft;
// the reference of the step types follows it.
const runbookSystem = `You write runbook files for Hearth, a self-hosted control plane for a homelab.
A runbook is a procedure an operator starts and follows: steps that act, check, ask or wait. When a step fails, the run stops and the operator retries it or rolls back what the run did.
You are given the transcript of a terminal session in which the operator did something by hand on a device: what the screen showed, prompts, the commands they typed and their output. Turn what they did into a reusable runbook. Answer with exactly one runbook, as YAML, and nothing else: no prose, no explanation, no Markdown fence.
The operator reviews your draft in an editor before anything is saved; Hearth's policy decides on every step when it runs.

The file:
- id: required, 1 to 64 lowercase letters, digits, - or _, starting with a letter or digit; pick a short descriptive one not among the existing runbooks
- description: one sentence saying what it does
- vars: optional, a map of names to values the steps repeat (a device, an address), used as ${{ vars.<name> }}
- steps: a list of at least one, at most 100, run in order; each has an id (lowercase letters, digits, - or _, unique in the file), a type, an optional description and the fields of its type, and nothing else

Step types:
- action: fields action (required) and rollback (optional), each one action as below; rollback undoes the action
- check: fields check (required: a mapping with the check's type and fields, as below), within (a duration: how long to keep trying, such as 2m) and every (a duration: how often)
- prompt: fields prompt (input for a line of text, or confirm for yes or no), message (required), secret (true for a value that must not be shown), timeout (a duration)
- wait: field duration (required, at most 24h)

Rules:
- Each command the operator ran that changed or verified something becomes an exec action on the device the session ran on, with the program as an absolute path when the transcript shows it (/usr/bin/apt-get, not apt-get) and its arguments as a YAML list. exec never runs a shell: no pipes, redirections, &&, ;, cd, globs or $VARIABLES. Split such a command into steps, or, if it cannot be split, write a prompt confirm step asking the operator to do it by hand, quoting the command in the message.
- Leave out what only looked around (ls, cat, less, history, clear, man), commands that failed and were retried, typos, and exit.
- Start with a prompt confirm step that asks for a go-ahead. Give a step that changes something a rollback when there is an obvious undo.
- Where the transcript shows the operator checking a result, verify it: a check step for a port, a URL, a DNS name, a Kubernetes or Talos node, or an exec action whose program fails when the result is wrong (such as systemctl is-active).
- Something the operator typed that is not a constant (a hostname, a version, a password they entered) becomes a prompt input step, with secret: true for a secret, or a var.
- Name only devices, clusters and plugins from the inventory, exactly as written there. The device the session ran on is named in the request.
- Durations are written like 10s, 5m, 1h. An exec action runs for at most 10m: give a long command a timeout.
- Values shown as [REDACTED] were removed before you saw them; never write one into the file. Passwords typed at a hidden prompt were never recorded.`

// RunbookSystem is the system prompt of a runbook draft: what the model is
// for, the step types, the action and check types, and an example.
func RunbookSystem() string {
	var b strings.Builder
	b.WriteString(runbookSystem)
	b.WriteString("\n\nAction types (for action and rollback):\n")
	writeRefs(&b, DraftActions)
	b.WriteString("\nCheck types (for a check step's check, as {type: tcp, address: ...}):\n")
	writeRefs(&b, RunbookChecks)
	b.WriteString("\nAn example, for a session that installed Docker on pi5:\n\n")
	b.WriteString(RunbookExample)
	return b.String()
}

// RunbookDraft is a request for a runbook from a recorded terminal session.
type RunbookDraft struct {
	// Device names the device the session ran on.
	Device string
	// Notes are the operator's own words on what the session did, if any.
	Notes string
	// Transcript is what the terminal showed, as text.
	Transcript string
	// Inventory names what the runbook may refer to.
	Inventory []Section
}

// PrepareRunbook builds the request for d: the inventory, then the
// transcript, cut to maxBytes (0: DefaultContextBytes) between them, then
// the user message redacted as a whole. The transcript comes last, so it
// gets what the inventory leaves.
func PrepareRunbook(d RunbookDraft, maxBytes int) Prepared {
	if maxBytes <= 0 {
		maxBytes = DefaultContextBytes
	}
	notes := strings.TrimSpace(d.Notes)
	if len(notes) > MaxRunbookNotes {
		notes = strings.ToValidUTF8(notes[:MaxRunbookNotes], "")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Write a runbook that does what this terminal session on device %s did.\n", d.Device)
	if notes != "" {
		fmt.Fprintf(&b, "The operator says:\n%s\n", notes)
	}
	b.WriteString("\nInventory of this hub:\n")
	sections := append(append([]Section(nil), d.Inventory...),
		Section{ID: "transcript", Title: "Terminal session on " + d.Device + " (what the screen showed)", Body: d.Transcript})
	var p Prepared
	remaining := maxBytes
	for i, s := range sections {
		share := remaining / (len(sections) - i)
		body := strings.TrimRight(s.Body, "\n")
		if body == "" {
			body = "(none)"
		}
		if len(body) > share {
			p.Truncated = append(p.Truncated, s.ID)
			body = cut(body, share, s.KeepTail)
		}
		remaining -= len(body)
		fmt.Fprintf(&b, "\n## %s\n%s\n", s.Title, body)
	}
	r := Redact(b.String())
	p.Redactions = r.Count
	p.Request = Request{System: RunbookSystem(), Messages: []Message{{Role: RoleUser, Content: r.Text}}}
	return p
}
