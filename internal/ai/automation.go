// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"fmt"
	"strings"
)

// MaxDraftRequest bounds the operator's description of an automation.
const MaxDraftRequest = 2000

// StepRef describes one step type of an automation file, as the model is
// told it: the types and fields of the web editor's forms
// (web/src/automations/schema.json), so that a draft opens in the visual
// editor. A test keeps the two the same.
type StepRef struct {
	Type   string
	Does   string
	Fields []FieldRef
}

// FieldRef is one field of a step type: its key, and how to write it.
type FieldRef struct {
	Key  string
	Note string
}

// DraftTriggers are the trigger types a draft may use.
var DraftTriggers = []StepRef{
	{Type: "manual", Does: "run by hand only"},
	{Type: "device", Does: "a device goes online or offline", Fields: []FieldRef{
		{"device", "device id, name or hostname; leave out for any device"},
		{"to", "required: online or offline"},
	}},
	{Type: "network", Does: "network discovery finds a new host, or one back after an hour", Fields: []FieldRef{
		{"event", "new or returned; leave out for both"},
		{"batch", "true: one firing per scan instead of one per host"},
	}},
	{Type: "metric", Does: "a metric stays above or below a threshold", Fields: []FieldRef{
		{"device", "device id, name or hostname; use with metric"},
		{"metric", "cpu, memory or disk (root filesystem), in percent"},
		{"query", "a PromQL query, instead of device and metric (needs Prometheus)"},
		{"above", "a number"},
		{"below", "a number"},
		{"for", "a duration, such as 5m: how long it must stay past the threshold"},
		{"every", "a duration: how often to read it (default 30s)"},
		{"timeout", "a duration: per read (default 5s)"},
	}},
	{Type: "http", Does: "an HTTP GET fails or returns the wrong status", Fields: []FieldRef{
		{"url", "required: the URL to get"},
		{"status", "the status to expect, a number; default any 2xx or 3xx"},
		{"from", "a device (id, name or hostname) whose agent runs the check instead of the hub"},
		{"every", "a duration: how often to check (default 10s)"},
		{"for", "a duration: how long it must keep failing before it fires (default 0: the first failure)"},
		{"timeout", "a duration: per check (default 5s)"},
	}},
	{Type: "dns", Does: "a DNS server does not resolve a name", Fields: []FieldRef{
		{"name", "required: the name to resolve, such as example.com"},
		{"server", "required: the DNS server to ask (such as a Pi-hole), host or host:port"},
		{"from", "a device whose agent runs the check instead of the hub; its own DNS server is then 127.0.0.1"},
		{"every", "a duration: how often to check (default 10s)"},
		{"for", "a duration: how long it must keep failing before it fires (default 0: the first failure)"},
		{"timeout", "a duration: per check (default 5s)"},
	}},
	{Type: "tcp", Does: "a TCP port does not accept connections", Fields: []FieldRef{
		{"address", "required: host:port"},
		{"from", "a device whose agent runs the check instead of the hub"},
		{"every", "a duration: how often to check (default 10s)"},
		{"for", "a duration: how long it must keep failing before it fires (default 0: the first failure)"},
		{"timeout", "a duration: per check (default 5s)"},
	}},
	{Type: "schedule", Does: "a cron schedule comes due", Fields: []FieldRef{
		{"cron", `required: five-field cron in quotes, such as "0 3 * * *", or @hourly, @daily, @every 15m`},
	}},
}

// DraftActions are the action types a draft may use.
var DraftActions = []StepRef{
	{Type: "log", Does: "writes a line to the hub log", Fields: []FieldRef{
		{"message", "required: the line; a template"},
	}},
	{Type: "webhook", Does: "sends one HTTP request", Fields: []FieldRef{
		{"url", "required: the URL"},
		{"method", "default POST"},
		{"headers", "a map of header names to values; values are templates"},
		{"body", "the request body; a template"},
		{"timeout", "a duration, default 10s, at most 1m"},
	}},
	{Type: "notify", Does: "sends a notification to a channel of the hub", Fields: []FieldRef{
		{"channel", "required: the name of one of the hub's notification channels, exactly as listed"},
		{"title", "a template"},
		{"message", "required: a template"},
	}},
	{Type: "plugin_command", Does: "runs a command an exec plugin declares", Fields: []FieldRef{
		{"plugin", "required: the plugin's name, as listed"},
		{"command", "required: one of the plugin's commands, as listed"},
		{"device", "the plugin's device id; a template"},
		{"args", "a map of the command's arguments"},
	}},
	{Type: "restart", Does: "restarts a service on a device", Fields: []FieldRef{
		{"device", "required: device id, name or hostname; a template"},
		{"service", "required: systemd:UNIT (such as systemd:pihole-FTL.service), systemd-user:UNIT or docker:CONTAINER"},
		{"timeout", "a duration, default 1m, at most 10m"},
	}},
	{Type: "check", Does: "runs an http, tcp or dns check once and fails the run if it fails: to verify a fix", Fields: []FieldRef{
		{"check", "required: http, tcp or dns"},
		{"url", "for http"},
		{"status", "for http: the status to expect"},
		{"address", "for tcp: host:port"},
		{"name", "for dns: the name to resolve"},
		{"server", "for dns: the server to ask"},
		{"from", "a device whose agent runs the check"},
		{"timeout", "a duration"},
	}},
	{Type: "exec", Does: "runs a program on a device (dangerous: needs a grant before it runs)", Fields: []FieldRef{
		{"device", "required: device id, name or hostname; a template"},
		{"command", "required: a YAML list, program then arguments, such as [/usr/bin/df, -h]; never a shell"},
		{"timeout", "a duration, default 1m, at most 10m"},
	}},
	{Type: "script", Does: "runs a sandboxed Starlark script on the hub", Fields: []FieldRef{
		{"source", "required: the script"},
		{"timeout", "a duration"},
		{"max_steps", "a number"},
		{"max_memory_mib", "a number"},
	}},
	{Type: "kube_restart", Does: "rolling restart of a Kubernetes workload", Fields: []FieldRef{
		{"cluster", "required: the cluster's name, as listed"},
		{"kind", "required: Deployment, StatefulSet or DaemonSet"},
		{"namespace", "required"},
		{"name", "required"},
	}},
	{Type: "kube_scale", Does: "sets the replicas of a Kubernetes workload", Fields: []FieldRef{
		{"cluster", "required: the cluster's name, as listed"},
		{"kind", "required: Deployment or StatefulSet"},
		{"namespace", "required"},
		{"name", "required"},
		{"replicas", "required: a number"},
	}},
	{Type: "kube_delete_pod", Does: "deletes a pod; its controller recreates it", Fields: []FieldRef{
		{"cluster", "required"}, {"namespace", "required"}, {"name", "required"},
	}},
	{Type: "kube_cordon", Does: "marks a Kubernetes node unschedulable", Fields: []FieldRef{
		{"cluster", "required"}, {"node", "required"},
	}},
	{Type: "kube_uncordon", Does: "marks a Kubernetes node schedulable again", Fields: []FieldRef{
		{"cluster", "required"}, {"node", "required"},
	}},
	{Type: "kube_node_delete", Does: "deletes a Kubernetes Node object (dangerous)", Fields: []FieldRef{
		{"cluster", "required"}, {"node", "required"},
	}},
	{Type: "kube_drain", Does: "cordons a Kubernetes node and evicts its pods (dangerous)", Fields: []FieldRef{
		{"cluster", "required"}, {"node", "required"}, {"timeout", "a duration, default 2m, at most 10m"},
	}},
}

// DraftExample is the example automation the model is shown; a test parses
// it with the hub's step types.
const DraftExample = `id: dns-watchdog
description: Restart Pi-hole on pi4 when DNS fails 3 times in a row, then tell me.
triggers:
  - id: dns-down
    type: dns
    name: example.com
    server: 192.168.1.2
    every: 10s
    for: 20s
actions:
  - id: restart-dns
    type: restart
    device: pi4
    service: systemd:pihole-FTL.service
  - id: verify
    type: check
    check: dns
    name: example.com
    server: 192.168.1.2
  - id: tell-me
    type: notify
    channel: phone
    title: DNS restarted
    message: "pihole-FTL on pi4 was restarted: {{ .Trigger.Error }}"
`

// draftSystem is the fixed part of the system prompt; the reference of the
// step types follows it.
const draftSystem = `You write automation files for Hearth, a self-hosted control plane for a homelab.
The operator describes what they want; you answer with exactly one automation, as YAML, and nothing else: no prose, no explanation, no Markdown fence.
The operator reviews your draft in an editor before anything is saved; Hearth's policy decides on every action when it runs.

The file:
- id: required, 1 to 64 lowercase letters, digits, - or _, starting with a letter or digit; pick a short descriptive one not among the existing automations
- description: one sentence saying what it does
- mode: optional, single (the default), queued or restart
- triggers: a list of at least one; any of them starts a run
- actions: a list of at least one, run in order; the first failure ends the run
- each step has a type, an optional id (lowercase letters, digits, - or _, unique in the file) and the fields of its type, and nothing else
- do not write conditions: none are available
- durations are written like 10s, 5m, 1h

Rules:
- Use only the step types and fields below.
- Name only devices, services, notification channels, clusters and plugins from the inventory, exactly as written there. If something the operator asks for is not in the inventory, use the closest match, or a clear placeholder name, and say so in the description.
- "Fails N times in a row" is a check with every and for: N checks every E apart fail for (N-1) x E, so 3 failures every 10s is for: 20s.
- A restart of a service is best followed by a check action that verifies it worked.
- Templates are Go text/template over the event that started the run: {{ .Trigger.At }} for every trigger; {{ .Trigger.Device }}, {{ .Trigger.Name }}, {{ .Trigger.Hostname }} and {{ .Trigger.State }} for device; {{ .Trigger.Value }} for metric; {{ .Trigger.Target }} and {{ .Trigger.Error }} for http, dns and tcp; {{ .Trigger.IP }}, {{ .Trigger.MAC }}, {{ .Trigger.Vendor }} for network. A field the trigger does not have is an error: with a schedule or manual trigger, use none. Quote a value that holds a template.
- Values shown as [REDACTED] were removed before you saw them; never write one into the file.`

// DraftSystem is the system prompt of a draft: what the model is for, the
// step types and their fields, and an example.
func DraftSystem() string {
	var b strings.Builder
	b.WriteString(draftSystem)
	b.WriteString("\n\nTrigger types:\n")
	writeRefs(&b, DraftTriggers)
	b.WriteString("\nAction types:\n")
	writeRefs(&b, DraftActions)
	b.WriteString("\nAn example, for \"restart pihole-FTL on pi4 when DNS fails 3 times, then notify me\":\n\n")
	b.WriteString(DraftExample)
	return b.String()
}

func writeRefs(b *strings.Builder, refs []StepRef) {
	for _, r := range refs {
		fmt.Fprintf(b, "- %s: %s\n", r.Type, r.Does)
		for _, f := range r.Fields {
			fmt.Fprintf(b, "    %s: %s\n", f.Key, f.Note)
		}
	}
}

// Draft is a request for an automation: the operator's words and what the
// hub has, by name.
type Draft struct {
	Request string
	// Inventory names what the draft may refer to: devices, notification
	// channels, clusters, plugins and the ids already taken.
	Inventory []Section
}

// PrepareDraft builds the request for d: the inventory cut to maxBytes (0:
// DefaultContextBytes), then the user message redacted as a whole. The
// system prompt is Hearth's own text, sent as is.
func PrepareDraft(d Draft, maxBytes int) Prepared {
	if maxBytes <= 0 {
		maxBytes = DefaultContextBytes
	}
	request := strings.TrimSpace(d.Request)
	if len(request) > MaxDraftRequest {
		request = strings.ToValidUTF8(request[:MaxDraftRequest], "")
	}
	var p Prepared
	var b strings.Builder
	fmt.Fprintf(&b, "Write an automation that does this:\n%s\n\nInventory of this hub:\n", request)
	remaining := maxBytes
	for i, s := range d.Inventory {
		share := remaining / (len(d.Inventory) - i)
		body := strings.TrimRight(s.Body, "\n")
		if body == "" {
			body = "(none)"
		}
		if len(body) > share {
			p.Truncated = append(p.Truncated, s.ID)
			body = cut(body, share, false)
		}
		remaining -= len(body)
		fmt.Fprintf(&b, "\n## %s\n%s\n", s.Title, body)
	}
	r := Redact(b.String())
	p.Redactions = r.Count
	p.Request = Request{System: DraftSystem(), Messages: []Message{{Role: RoleUser, Content: r.Text}}}
	return p
}

// RetryDraft continues req after an answer that did not validate: the
// answer, then the problems, both redacted. It returns the new request and
// how many values were redacted.
func RetryDraft(req Request, answer string, problems []string) (Request, int) {
	a := Redact(answer)
	var b strings.Builder
	b.WriteString("That file is not valid. Hearth's validator says:\n")
	for _, p := range problems {
		fmt.Fprintf(&b, "- %s\n", p)
	}
	b.WriteString("\nAnswer with the whole corrected file, as YAML only.")
	q := Redact(b.String())
	next := req
	next.Messages = append(append([]Message(nil), req.Messages...),
		Message{Role: RoleAssistant, Content: a.Text},
		Message{Role: RoleUser, Content: q.Text})
	return next, a.Count + q.Count
}

// ExtractYAML takes the automation out of a model's answer: inside a
// Markdown fence if there is one, else from its first top-level key on.
func ExtractYAML(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if i := strings.Index(text, "```"); i >= 0 {
		rest := text[i+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:] // the fence's language, if any
			if j := strings.Index(rest, "```"); j >= 0 {
				rest = rest[:j]
			}
			return strings.TrimSpace(rest) + "\n"
		}
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "id:") || strings.HasPrefix(l, "description:") || strings.HasPrefix(l, "triggers:") {
			return strings.TrimSpace(strings.Join(lines[i:], "\n")) + "\n"
		}
	}
	return strings.TrimSpace(text) + "\n"
}
