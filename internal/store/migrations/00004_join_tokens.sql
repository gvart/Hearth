-- SPDX-License-Identifier: AGPL-3.0-only
-- Single-use tokens that let a new hub join a Raft cluster. Kept apart from
-- enrollment tokens so neither kind can be spent as the other.

-- +goose Up
CREATE TABLE join_tokens (
    hash       BLOB    PRIMARY KEY, -- SHA-256 of the token secret; the secret is never stored
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
) STRICT;

-- +goose Down
DROP TABLE join_tokens;
