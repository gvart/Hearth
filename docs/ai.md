---
title: Explain with AI
description: Ask a language model you choose (a local Ollama, any OpenAI-compatible server, or Anthropic) what is wrong with a device, to draft an automation, or to turn a recorded terminal session into a runbook. Off by default, redacted, audited, and it never runs anything.
---

A device page has an **Explain** card: ask "why is it slow?", or nothing at all, and the hub sends what it
knows about the device to a language model and shows the answer. `hearth ai explain <device>` does the
same from a terminal. The **New automation** editor has a **Write it with AI** card: describe what you want,
and the model drafts the file for you to review and save ([below](#draft-an-automation)). A terminal
session you choose to record becomes a draft runbook
([below](#capture-a-runbook-from-a-terminal-session)).

- **Off by default.** Hearth works fully without it. An admin turns it on by choosing a provider.
- **Bring your own model.** Any OpenAI-compatible chat completions API (Ollama, LM Studio, vLLM,
  llama.cpp's server, OpenAI), or Anthropic's Messages API. With a local model nothing leaves your lab.
- **It never acts.** The answer is text. A fix it suggests is a suggestion: you take it through
  Hearth's usual controls, where [policy](guardrails.md) decides, or on the device yourself.
- **You see what is sent.** Credentials are redacted first, the first explanation in a browser shows
  the request before sending it, and every answer keeps **What was sent** next to it.
- **Audited.** Every question is the policy action `ai.explain` (class `read`), in the audit log with the
  provider, the model and the sizes, never the question, the evidence or the answer.

## Set it up with Ollama (everything stays local)

Run [Ollama](https://ollama.com) on any machine of the lab, pull a model, and let it listen where the hub
can reach it:

```sh
ollama pull llama3.2
OLLAMA_HOST=0.0.0.0 OLLAMA_CONTEXT_LENGTH=8192 ollama serve
```

Then, in the web UI, open **Settings, AI**, choose **OpenAI-compatible**, and enter:

- **Address**: `http://<ollama-host>:11434/v1` (the address ends in `/v1`)
- **Model**: `llama3.2` (any model `ollama list` shows)
- **API key**: leave it empty

or, from a terminal:

```sh
hearth ai set --provider openai --base-url http://ollama.lan:11434/v1 --model llama3.2
```

LM Studio (`http://<host>:1234/v1`), vLLM (`http://<host>:8000/v1`) and llama.cpp's `llama-server`
(`http://<host>:8080/v1`) work the same way. For OpenAI itself, use `https://api.openai.com/v1`, a
model such as `gpt-4.1-mini`, and an API key.

**Context size.** Many Ollama versions give a model a small context window (a few thousand tokens)
unless told otherwise, and cut a longer request without saying so. Start Ollama with
`OLLAMA_CONTEXT_LENGTH=8192` (or more), or lower what the hub sends with `max_context_bytes` (below). A
question sends at most about 24 KiB of evidence by default, roughly 6000 tokens.

## Set it up with Anthropic

Create an API key in the Anthropic Console, then in **Settings, AI** choose **Anthropic** and paste the
key. Leave the address and the model empty for `https://api.anthropic.com` and the default model,
`claude-opus-5-5`; name another model to use it. Requests opt into Anthropic's server-side refusal
fallbacks, so a question the model declines is answered by the fallback model the API picks; if it is
still refused, Hearth says the model gave no answer. From a terminal:

```sh
HEARTH_AI_API_KEY=sk-ant-... hearth ai set --provider anthropic
# or: hearth ai set --provider anthropic --api-key-file ~/anthropic.key --model claude-sonnet-5-5
```

The key is write-only: the hub stores it sealed (encrypted with a key derived from the hub CA key, as
notification credentials are), never logs it, never audits it and never returns it, to the web UI or
the API. A stored key is only ever sent to the provider and address it was entered for: change either
and you enter the key again.

## Settings

The settings are the configuration document `ai.yaml`, in the hub's store like `notify.yaml`: the same
on every hub of a cluster, and imported and exported with `hearth config import` and
`hearth config export`. Saving them is `config.import` through policy, and the web UI asks for the admin
password again.

```yaml
provider: openai               # openai (any OpenAI-compatible API) or anthropic; absent: AI is off
base_url: http://ollama.lan:11434/v1
model: llama3.2
api_key: ""                    # required for anthropic; optional for a local server
max_tokens: 0                  # bound on an answer (0: 4096 for anthropic, the server's own for openai)
timeout_seconds: 0             # bound on one answer (0: 300)
max_context_bytes: 0           # bound on the evidence of one question (0: 24576)
```

`hearth ai status` shows them, without the key. `hearth ai set --off` (or **Off** in the web UI) turns AI
off.

## What is sent

For one device, most useful first, each cut to share the size limit:

| Section     | What it holds                                                                                   |
|-------------|-------------------------------------------------------------------------------------------------|
| `device`    | name, id, hostname, status, last seen, boot time, labels, OS, kernel, agent version, CPU, memory, disks with their use, interfaces with their addresses |
| `metrics`   | for each metric of the last 6 hours (CPU, memory, disk, temperature, network): now, minimum, average and maximum |
| `audit`     | the last 30 audit log entries whose target is the device (its id, name or hostname): time, action, actor, decision and result |
| `log:<source>` | only if you ask for it: the last 200 lines of a log the device's agent allows, such as `systemd:nginx.service` |

and your question, or "Is anything wrong with it?" if you ask none. A short system prompt tells the model
what Hearth is, to cite the sections it relies on (such as `[metrics]`), and that it cannot run anything.

A log tail is read as its own `device.logs` action, audited, and only if the device's
[capability ceiling](guardrails.md) allows that source; a log that cannot be read is left out with a note,
and the explanation goes on without it. "Recent events" are the device's status and the audit entries
about it: the hub keeps no other history of a device's events.

**Preview first.** **Preview what is sent** (or `hearth ai explain <device> --preview`) gathers and redacts
the evidence and sends nothing, so you can read every byte. The first explanation in a browser shows the
preview before it sends; after that, each answer has **What was sent** below it
(`hearth ai explain --show-sent` prints it).

## How redaction works

Before anything leaves the hub, the whole request (your question too) goes through a redactor that
replaces with `[REDACTED]`:

- PEM blocks: private keys and certificates (a block cut off before its `END` line is redacted to the end)
- SSH key bodies (`ssh-ed25519 AAAA...`)
- `Authorization` and `Proxy-Authorization` headers, and any `Bearer` token
- passwords in URLs (`postgres://app:[REDACTED]@db`)
- Hearth's own enrollment, join and MCP tokens
- well-known API key formats: Anthropic and OpenAI (`sk-...`), GitHub, GitLab, Slack, AWS access key ids,
  Google API keys, and JSON web tokens
- the value of any key that names a secret: `PASSWORD=...`, `api_key: ...`, `"token": "..."`,
  `client_secret = ...`, `X-Api-Key: ...`, cookies and session ids

It errs on the side of hiding (`token_count: 5` loses its 5), but it is pattern matching: a secret with no
recognisable shape or name, in a log line, can get through. Read the preview before you send a log tail to
a model outside your lab, or use a local model. The count of redacted values is shown with every answer.

## Policy and audit

`ai.explain` is a `read` action of the web actor; the CLI uses the hub's web API. A policy that denies
reads to the web UI denies it, and nothing is gathered or sent. Its audit entry records the provider, the
model, the provider's host, whether it was a preview, the log sources named, the bytes sent, the number
of values redacted, the bytes and tokens of the answer, and whether it succeeded, never the text itself.

The model never gets a tool, a token or a way to act: the hub sends text and reads text back. Any step its
answer suggests is shown as plain text, never as a button; you run it yourself, through policy.

## Draft an automation

Open **Automations, New automation** and describe what the automation should do in the **Write it with
AI** card, such as "restart pihole-FTL on the dns pi when DNS fails 3 times, then notify me". The hub:

1. builds a prompt from the automation schema (the step types and fields of the visual editor, the same
   list the editor's forms use) and the names of what it has: its devices, with the services their agents
   let automations restart, the programs they may run and whether they run checks; its notification
   channels; its Kubernetes clusters; its plugins and their commands; and the automation ids already
   taken. Names only, no facts, metrics or logs, redacted like an explanation;
2. asks the model, takes the YAML out of its answer, and validates it with the same validator a save from
   the editor uses;
3. if the hub refuses it, sends the model its problems, line by line, and asks once more. Two answers at
   most;
4. returns the draft. **Nothing is saved, enabled or run.**

The draft opens in the editor, unsaved. A valid one gets a dry run at once: what the automation would do,
and what policy would decide on saving it and on each of its actions. One the hub still refuses opens in
the YAML view with its problems, to fix by hand or describe again. Review every step, then **Save**: the
save is `automation.apply`, through policy and audited as any edit, and the actions are decided by policy
each time they run. **What was sent** shows the prompt, and **Preview what is sent** shows it without
sending anything.

A draft for the request above, on a hub with a device `pi4` that may restart `systemd:pihole-FTL.service`
and a channel `phone`:

```yaml
id: dns-watchdog
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
```

From a terminal, `hearth ai automation "<what it should do>"` prints only the YAML, so it can go straight
to a file; notes and any problems go to stderr, and the command fails if the draft does not validate.
`--preview` prints what would be sent. Save a file with `hearth config import` or paste it into the
editor:

```sh
hearth ai automation "notify me on phone when the nas goes offline" > automations/nas-down.yaml
```

A draft is the policy action `ai.automation.draft`, class `read`, of the web actor: a policy that denies
reads to the web UI denies it, and nothing is gathered or sent. Its audit entry records the provider, the
model, its host, whether it was a preview, the bytes sent, the values redacted, the number of answers,
their bytes and tokens, and whether the draft validated: never the description, the names sent or the
draft. The prompt is about 8 KiB (some 2000 tokens) before the inventory: start Ollama with
`OLLAMA_CONTEXT_LENGTH=8192`, as above, or a small default context window cuts it without saying so.

## Capture a runbook from a terminal session

Do something once by hand in a device's [web terminal](terminal.md), such as adding a node, and let the
model turn it into a [runbook](runbooks.md) you can run again. A terminal is recorded only when you
ask for it, for that session:

1. On the device's page, choose **Record for a runbook** next to **Terminal**, or tick **Record for a
   runbook** on the terminal page before **Connect**. The hub asks for the admin password again. While
   AI is off the choice is not offered, and one line links to **Settings, AI**.
2. Work as usual. The terminal shows a red **Recording for a runbook** badge as long as the hub
   records the session; the hub sends the badge when the session opens, and a terminal opened without
   the choice never has one.
3. Close the session (`exit`, or close the tab). The terminal, and the device's page under **Recorded
   for a runbook**, offer **Make a runbook**, with an optional note on what you did, **Preview what is
   sent** and **Discard**.
4. The draft opens in the runbook editor, unsaved, checked and planned. Review every step, then
   **Save…**, which is `config.import`, decided by policy and audited as any edit. Nothing is saved,
   started or run until you do.

What is recorded:

- **What the terminal shows, never what is typed.** The shell echoes a command as you type it, so the
  commands and their output are there. A password prompt (sudo, ssh, `read -s`) turns the echo off, so
  what you type at it is never on the screen and never recorded.
- **At most 256 KiB**; the badge says when the recording is full, and the rest of the session is not
  recorded.
- **In the memory of the hub that serves the terminal only**: never in the store, so never replicated to
  other hubs or put in a backup, and never in a log or the audit log. It is deleted when a runbook is
  made from it (once the model answered; a provider error keeps it for another try), when you discard
  it, and one hour after its session ended. A hub restart loses it. At most 8 recordings are held at a
  time.
- **Redacted before it is sent**, with the same patterns as explanations (see
  [How redaction works](#how-redaction-works)). Redaction recognises known formats, not every secret: a
  password on a command line, such as `mysql -pSECRET`, is sent as is. **Preview what is sent** shows
  every byte before anything leaves the hub.

The model is told the runbook step types, the action and check types and their fields, an example, the
names of the hub's devices (with the programs their agents let actions run), channels, clusters and
plugins, and the runbook ids already taken. It is asked to turn each command that changed or verified
something into an `exec` action of the device, with a confirmation first, rollbacks where there is an
obvious undo, and checks for what you verified. An `exec` action runs a program, never a shell: a
command with pipes or `&&` becomes a step you do by hand. The hub validates the answer as the editor's
save does and, if it refuses it, asks once more with the problems, as for an automation draft. An
`exec` step runs only if the device's ceiling allows that program (**Capabilities**), and it is
dangerous: policy decides on it when the runbook runs.

Recording a session is the policy action `device.shell.record`, class `dangerous`, of the web actor
only, decided and audited before the session's own `device.shell`: refused, no shell opens at all. It
also needs the admin password entered again in the last five minutes, AI set up, and room for another
recording. Under a policy that holds dangerous web actions for approval, a recorded session waits for
two approvals: the recording's, then the terminal's. Both `device.shell` entries of a recorded session
name its recording. Making the draft is `ai.runbook.draft`, class `read`, of the web actor; its audit
entry holds the provider, the model, its host, the recording's id and size, the bytes sent, the values
redacted, the answers and tokens, and whether the draft validated: never any text.

In a cluster, the recording is held by the hub the device's agent streams to, which serves its
terminal; the recording requests are sent there from any hub. If the agent moved to another hub in
between, that hub has no such recording.

From a terminal, list a device's recordings and draft from one; only the YAML goes to stdout:

```sh
hearth ai recordings pi5
hearth ai runbook pi5 <recording-id> --notes "added a k3s worker" > runbooks/add-k3s-worker.yaml
```

`--preview` prints what would be sent and keeps the recording. A session can be recorded only from the
web terminal: there is no terminal in the CLI.

## Errors

| Error code                     | Meaning                                                                 |
|--------------------------------|-------------------------------------------------------------------------|
| `ai_off`                       | no provider is set up                                                   |
| `ai_auth`                      | the provider refused the API key (401 or 403)                           |
| `ai_not_found`                 | no such model, or a wrong address (404); for Ollama, `ollama pull` it    |
| `ai_rate_limited`              | the provider is rate limiting, or the account is out of credit (429)    |
| `ai_unavailable`               | the provider cannot be reached, or failed (5xx)                         |
| `ai_timeout`                   | no answer within `timeout_seconds`: a small machine wants a smaller model |
| `ai_error`                     | the model answered nothing, or the provider refused the request          |

Redirects are not followed, so the key never goes to another address: give the provider's final address.
