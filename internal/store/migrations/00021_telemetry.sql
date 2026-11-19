-- SPDX-License-Identifier: AGPL-3.0-only
-- The admin's answer to "Share anonymous usage stats?" (docs/telemetry.md).
-- One row at most: none until the admin answers. install_id is random, made
-- when the admin opts in, and empty while telemetry is off. last_sent_at is
-- the last attempt to send (unix ms, 0 for never), so a restart or a failover
-- does not send again before a week has passed.

-- +goose Up
CREATE TABLE telemetry (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    enabled      INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    install_id   TEXT    NOT NULL,
    answered_at  INTEGER NOT NULL,
    last_sent_at INTEGER NOT NULL DEFAULT 0
) STRICT;

-- +goose Down
DROP TABLE telemetry;
