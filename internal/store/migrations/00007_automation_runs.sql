-- SPDX-License-Identifier: AGPL-3.0-only
-- Run history of automations: one row per run, written by the cluster leader
-- when the run ends. Each automation keeps only its newest runs (the command
-- that records a run prunes the rest).

-- +goose Up
CREATE TABLE automation_runs (
    id            TEXT    PRIMARY KEY,
    automation_id TEXT    NOT NULL,
    trigger_id    TEXT    NOT NULL,
    started_at    INTEGER NOT NULL,
    finished_at   INTEGER NOT NULL,
    status        TEXT    NOT NULL,
    error         TEXT    NOT NULL DEFAULT '',
    steps         TEXT    NOT NULL DEFAULT '[]' -- JSON array of step results
) STRICT;

CREATE INDEX automation_runs_automation ON automation_runs (automation_id, started_at);

-- +goose Down
DROP TABLE automation_runs;
