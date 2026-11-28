---
title: Explain with AI
description: Ask a language model you choose (a local Ollama, any OpenAI-compatible server, or Anthropic) what is wrong with a device. Off by default, redacted, audited, and it never runs anything.
---

A device page has an **Explain** card: ask "why is it slow?", or nothing at all, and the hub sends what it
knows about the device to a language model and shows the answer. `hearth ai explain <device>` does the
same from a terminal.

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

## Errors

| Error code                     | Meaning                                                                 |
|--------------------------------|-------------------------------------------------------------------------|
| `ai_off`                       | no provider is set up                                                   |
| `ai_auth`                      | the provider refused the API key (401 or 403)                           |
| `ai_not_found`                 | no such model, or a wrong address (404); for Ollama, `ollama pull` it    |
| `ai_rate_limited`              | the provider is rate limiting, or the account is out of credit (429)    |
| `ai_unavailable`               | the provider cannot be reached, or failed (5xx)                         |
| `ai_timeout`                   | no answer within `timeout_seconds`: a small machine wants a smaller model |

Redirects are not followed, so the key never goes to another address: give the provider's final address.
