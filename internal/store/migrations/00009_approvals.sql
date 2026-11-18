-- SPDX-License-Identifier: AGPL-3.0-only
-- Pending approvals: actions policy holds for confirmation ("confirm" mode)
-- until an operator approves or denies them, or they expire. Each decision is
-- also in the audit log; this table is the queue.

-- +goose Up
CREATE TABLE approvals (
    id         TEXT    PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    actor_kind TEXT    NOT NULL,
    actor_id   TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    class      TEXT    NOT NULL,
    target     TEXT    NOT NULL DEFAULT '',
    detail     TEXT    NOT NULL DEFAULT '{}',
    status     TEXT    NOT NULL DEFAULT 'pending', -- pending, approved, denied, expired
    decided_by TEXT    NOT NULL DEFAULT '',
    decided_at INTEGER
) STRICT;

CREATE INDEX approvals_status ON approvals (status, created_at);

-- +goose Down
DROP TABLE approvals;
