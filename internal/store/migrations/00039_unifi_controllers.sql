-- SPDX-License-Identifier: AGPL-3.0-only
-- UniFi Network controllers adopted through their API (#365). The connection
-- (URL, controller kind, site, API key or local username and password, and a
-- pinned certificate fingerprint) is sealed (AES-256-GCM) before it reaches
-- the store, so neither this table, the replication stream nor a snapshot
-- ever holds a credential in the clear.

-- +goose Up
CREATE TABLE unifi_controllers (
    id         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    connection BLOB    NOT NULL, -- sealed: nonce || ciphertext
    created_at INTEGER NOT NULL,
    _hlc       INTEGER NOT NULL DEFAULT 0,
    _origin    TEXT    NOT NULL DEFAULT '',
    _deleted   INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
) STRICT;

-- +goose Down
DROP TABLE unifi_controllers;
