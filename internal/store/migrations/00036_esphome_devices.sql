-- SPDX-License-Identifier: AGPL-3.0-only
-- ESPHome devices adopted through their native API (#78). The connection
-- (address, encryption key or legacy password, and whether calls are
-- allowed) is sealed (AES-256-GCM) before it reaches the store, so neither
-- this table, the replication stream nor a snapshot ever holds the key in
-- the clear.

-- +goose Up
CREATE TABLE esphome_devices (
    id         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    connection BLOB    NOT NULL, -- sealed: nonce || ciphertext
    created_at INTEGER NOT NULL,
    _hlc       INTEGER NOT NULL DEFAULT 0,
    _origin    TEXT    NOT NULL DEFAULT '',
    _deleted   INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
) STRICT;

-- +goose Down
DROP TABLE esphome_devices;
