-- SPDX-License-Identifier: AGPL-3.0-only
-- OPNsense firewalls adopted through their REST API (#364). The connection (URL,
-- API key and secret, and a pinned certificate fingerprint) is sealed
-- (AES-256-GCM) before it reaches the store, so neither this table, the
-- replication stream nor a snapshot ever holds the key or secret in the clear.

-- +goose Up
CREATE TABLE opnsense_firewalls (
    id         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    connection BLOB    NOT NULL, -- sealed: nonce || ciphertext
    created_at INTEGER NOT NULL,
    _hlc       INTEGER NOT NULL DEFAULT 0,
    _origin    TEXT    NOT NULL DEFAULT '',
    _deleted   INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
) STRICT;

-- +goose Down
DROP TABLE opnsense_firewalls;
