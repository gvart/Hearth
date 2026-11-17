-- SPDX-License-Identifier: AGPL-3.0-only
-- Admin credential and web sessions (T6). Timestamps are INTEGER unix milliseconds (UTC).

-- +goose Up
-- A single row: the admin password as an argon2id PHC string.
CREATE TABLE admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT    NOT NULL
) STRICT;

CREATE TABLE sessions (
    hash       BLOB    PRIMARY KEY, -- SHA-256 of the session secret; the secret is never stored
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX sessions_expires_at ON sessions (expires_at);
CREATE INDEX devices_status_last_seen ON devices (status, last_seen);

-- +goose Down
DROP INDEX devices_status_last_seen;
DROP TABLE sessions;
DROP TABLE admin;
