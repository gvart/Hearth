-- SPDX-License-Identifier: AGPL-3.0-only
-- AI settings (#59): ai.yaml, the provider, model and API key the hub asks
-- to explain what is wrong, is a configuration document of its own kind,
-- sealed like notify.yaml (it holds a credential). SQLite cannot change a
-- CHECK constraint in place, so the table is built again with the new kind,
-- every row and version column copied as is.

-- +goose Up
CREATE TABLE config_docs_new (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('policy', 'notify', 'automation', 'runbook', 'ai')),
    name       TEXT NOT NULL,
    content    BLOB NOT NULL,
    digest     TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    _hlc       INTEGER NOT NULL DEFAULT 0,
    _origin    TEXT NOT NULL DEFAULT '',
    _deleted   INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
);
INSERT INTO config_docs_new (id, kind, name, content, digest, updated_at, updated_by, _hlc, _origin, _deleted)
    SELECT id, kind, name, content, digest, updated_at, updated_by, _hlc, _origin, _deleted FROM config_docs;
DROP TABLE config_docs;
ALTER TABLE config_docs_new RENAME TO config_docs;

-- +goose Down
DELETE FROM config_docs WHERE kind = 'ai';
CREATE TABLE config_docs_old (
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
INSERT INTO config_docs_old SELECT id, kind, name, content, digest, updated_at, updated_by, _hlc, _origin, _deleted FROM config_docs;
DROP TABLE config_docs;
ALTER TABLE config_docs_old RENAME TO config_docs;
