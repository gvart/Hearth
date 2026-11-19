-- SPDX-License-Identifier: AGPL-3.0-only
-- Runs of runbooks: multi-step procedures that outlive a hub restart and a
-- change of cluster leader. version is bumped by every write, which is
-- accepted only from the version it read, so that a deposed leader cannot
-- advance a run. source is the runbook file the run started from, sealed.
-- state is a JSON document of the run's steps and log; secret prompt answers
-- are never in it.

-- +goose Up
CREATE TABLE runbook_runs (
    id          TEXT PRIMARY KEY,
    runbook_id  TEXT NOT NULL,
    status      TEXT NOT NULL,
    version     INTEGER NOT NULL,
    started_by  TEXT NOT NULL,
    started_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    finished_at INTEGER NOT NULL DEFAULT 0,
    source      BLOB NOT NULL,
    state       TEXT NOT NULL
);
CREATE INDEX runbook_runs_started ON runbook_runs (started_at DESC);
CREATE INDEX runbook_runs_runbook ON runbook_runs (runbook_id, started_at DESC);
CREATE INDEX runbook_runs_open ON runbook_runs (status) WHERE finished_at = 0;

-- +goose Down
DROP TABLE runbook_runs;
