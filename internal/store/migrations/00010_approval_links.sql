-- SPDX-License-Identifier: AGPL-3.0-only
-- Approval links: single-use secrets, sent to a notification channel, that
-- approve or deny one pending approval. Only the secret's SHA-256 hash is
-- stored; a link expires with its approval and is spent by its first use.

-- +goose Up
CREATE TABLE approval_links (
    hash        BLOB    PRIMARY KEY,
    approval_id TEXT    NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
) STRICT;

-- +goose Down
DROP TABLE approval_links;
