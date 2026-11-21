# Agent idle memory budget: 25 MB

**Status:** decided 2026-11-20 by the owner. Discussion: [#209](https://github.com/gvart/hearth/issues/209).

## Decision

The agent's idle memory budget (CLAUDE.md principle 4) goes from 20 MB to 25 MB RSS. "Near-zero CPU"
and "Measure it" stay as they are. `internal/agent/rss_test.go` enforces the new limit
(`rssLimit = 25 << 20`).

## Why

- On the Pi 5, main's agent idles at about 19.9 MB and peaks at about 20.2 MB, so it fails the 20 MB
  gate after about 10 minutes of plain idle. The Pi 4 passes with about 0.3 MB to spare.
- Most of the RSS is file-backed binary pages, faulted in by package init. Every linked package's
  init runs in agent mode too, so hub-only code costs agent memory even though the agent never
  uses it. Making hearth's own hub-only state lazy saves at most about 384 kB.
- Getting back under 20 MB needs a separate agent-only build (measured at about 15 MB). That breaks
  the one-binary decision in #187, so it was not taken.
- Hub-only features add about 0.8–0.9 MB of agent RSS each: Starlark (#222) and the MQTT broker
  (#227).

The owner allows 2–5 MB more. 25 MB covers today's agent plus those features and leaves room for a
few more.

## Releasing init-only binary pages (#263)

Most of the idle agent's RSS was file pages of the binary: package init of every linked package faults
in much of it, and some kernels (the CI runner's 7.0 azure kernel) keep nearly the whole binary mapped.
Thirty seconds after start and after each connection, the agent now drops the page table entries of
the binary's read-only, unmodified mappings (`MADV_DONTNEED`, `internal/agent/image_linux.go`). The
pages stay in the page cache; the code the agent still runs faults back in.

| `TestAgentIdleRSS`, VmRSS after 1 min | before | after |
|---|---|---|
| local, linux/arm64 (kernel 6.8) | 19,976–20,324 kB | 7,952–8,972 kB |
| CI, test alone (ubuntu-latest, amd64) | 24,172–24,800 kB | 9,976–11,404 kB |
| CI, inside `go test -race ./...` | 24.4–25.2 MB (#262) | 9,976 kB |

Two consequences:

- Over a longer idle more code faults back in, then it levels off: after 10 minutes 13.2 MB locally
  and 15.0 MB on CI (14.2 MB from 3 minutes on).
- The peak (VmHWM) is unchanged, about 20.5 MB locally and 24.5–25 MB on CI, as init still touches
  the pages before they are released. A binary that grows still shows up there, and in the idle
  working set, but no longer one for one in the idle RSS. New dependencies still need to justify what
  they add.

## What stays the same

The agent is still measured, not estimated: the RSS test runs the release build for a minute on
Linux, and real hardware (Pi 4, Pi 5) is the reference. New dependencies still need to justify the
memory they add to an idle agent.
