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

## What stays the same

The agent is still measured, not estimated: the RSS test runs the release build for a minute on
Linux, and real hardware (Pi 4, Pi 5) is the reference. New dependencies still need to justify the
memory they add to an idle agent.
