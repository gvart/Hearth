-- SPDX-License-Identifier: AGPL-3.0-only
-- Read-only tokens of dashboards such as Homepage (docs/homepage.md). A token
-- reads the dashboard summary and nothing else; the ID is its identity in
-- policy and the audit log (token/<id>). Only the SHA-256 hash of the secret
-- is stored. expires_at and revoked_at are unix ms, NULL for never and not
-- revoked.

-- +goose Up
CREATE TABLE dashboard_tokens (
    id         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL,
    hash       BLOB    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
) STRICT;

-- +goose Down
DROP TABLE dashboard_tokens;
