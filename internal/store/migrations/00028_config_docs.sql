-- SPDX-License-Identifier: AGPL-3.0-only
-- Configuration documents (docs/design/ap-cluster.md §7): policy.yaml,
-- notify.yaml, each automation file and each runbook file, held in the store
-- instead of on each hub's disk, so every hub runs the same configuration.
-- id is kind/name. content is the file as imported, byte for byte, except
-- for notify, whose content is sealed with a key derived from the hub CA key
-- (it holds credentials). digest is the SHA-256, in hex, of what content
-- holds. A row is versioned like every replicated row (00027): a document
-- merges last-writer-wins, and a deleted one is a tombstone without content.

-- +goose Up
CREATE TABLE config_docs (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('policy', 'notify', 'automation', 'runbook')),
    name       TEXT NOT NULL,
    content    BLOB NOT NULL,
    digest     TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    _hlc       INTEGER NOT NULL DEFAULT 0,
    _origin    TEXT NOT NULL DEFAULT '',
    _deleted   INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
);

-- +goose Down
DROP TABLE config_docs;
