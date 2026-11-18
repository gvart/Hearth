-- SPDX-License-Identifier: AGPL-3.0-only
-- Bearer tokens of MCP clients. The name is the client's identity in policy
-- and the audit log (mcp/<name>); it is never reused, even once revoked.

-- +goose Up
CREATE TABLE mcp_tokens (
    name       TEXT    PRIMARY KEY,
    hash       BLOB    NOT NULL UNIQUE, -- SHA-256 of the token; the token is never stored
    scope      TEXT    NOT NULL,        -- the highest class it may request: read, safe or dangerous
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;

-- +goose Down
DROP TABLE mcp_tokens;
