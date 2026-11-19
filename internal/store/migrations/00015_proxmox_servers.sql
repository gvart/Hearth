-- SPDX-License-Identifier: AGPL-3.0-only
-- Proxmox VE servers adopted through an API token. The connection (address,
-- token and trust anchor) is sealed (AES-256-GCM) before it reaches the
-- store, so neither this table, the Raft log nor a snapshot ever holds the
-- token in the clear.

-- +goose Up
CREATE TABLE proxmox_servers (
    id         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    connection BLOB    NOT NULL, -- sealed: nonce || ciphertext
    created_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE proxmox_servers;
