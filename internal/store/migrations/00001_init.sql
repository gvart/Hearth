-- SPDX-License-Identifier: AGPL-3.0-only
-- Timestamps are INTEGER unix milliseconds (UTC). JSON columns hold TEXT.

-- +goose Up
CREATE TABLE devices (
    id         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL DEFAULT '',
    hostname   TEXT    NOT NULL DEFAULT '',
    os         TEXT    NOT NULL DEFAULT '',
    arch       TEXT    NOT NULL DEFAULT '',
    facts      TEXT    NOT NULL DEFAULT '{}',
    labels     TEXT    NOT NULL DEFAULT '{}',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'unknown'
) STRICT;

CREATE TABLE tokens (
    hash       BLOB    PRIMARY KEY, -- SHA-256 of the token secret; the secret is never stored
    labels     TEXT    NOT NULL DEFAULT '{}',
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
) STRICT;

CREATE TABLE certs (
    serial     TEXT    PRIMARY KEY,
    device_id  TEXT    NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    revoked_at INTEGER
) STRICT;

CREATE INDEX certs_device_id ON certs (device_id);

CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    actor_kind TEXT    NOT NULL,
    actor_id   TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    target     TEXT    NOT NULL DEFAULT '',
    decision   TEXT    NOT NULL,
    result     TEXT    NOT NULL DEFAULT '',
    detail     TEXT    NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX audit_log_ts ON audit_log (ts);

-- The audit log is append-only.
-- +goose StatementBegin
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP TABLE audit_log;
DROP TABLE certs;
DROP TABLE tokens;
DROP TABLE devices;
