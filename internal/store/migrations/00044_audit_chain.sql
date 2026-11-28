-- SPDX-License-Identifier: AGPL-3.0-only
-- Tamper evidence for the audit log (#387). A master seals each entry it
-- appends: chain_mac is an HMAC-SHA256 of the entry, keyed by a key derived
-- (HKDF) from the hub CA key of generation chain_kid, over the entry's
-- columns and its place in the master's own chain: chain_origin (the
-- master), chain_seq (1, 2, 3, ... per master) and chain_prev (the
-- chain_mac of the master's entry before). A member without the CA key
-- cannot make a valid entry; a missing sequence number is a deleted entry.
-- Entries written before sealing started (the oldest sealed entry of the
-- cluster) have none of these: legacy. One without a seal written since is
-- not.

-- +goose Up
ALTER TABLE audit_log ADD COLUMN chain_origin TEXT;
ALTER TABLE audit_log ADD COLUMN chain_seq INTEGER;
ALTER TABLE audit_log ADD COLUMN chain_prev TEXT;
ALTER TABLE audit_log ADD COLUMN chain_kid TEXT;
ALTER TABLE audit_log ADD COLUMN chain_mac TEXT;

CREATE INDEX audit_log_chain ON audit_log (chain_origin, chain_seq) WHERE chain_origin IS NOT NULL;
CREATE INDEX audit_log_sealed_ts ON audit_log (ts) WHERE chain_mac IS NOT NULL;

-- The audit MAC keys of earlier hub CAs, each sealed (AES-256-GCM) with a key
-- derived from the hub CA key the masters hold now, and sealed again with the
-- new one when a rotation finishes: entries sealed before a rotation still
-- verify after it. A master table: storage-only members never hold it.
CREATE TABLE audit_keys (
    id         TEXT    PRIMARY KEY, -- the key id, chain_kid
    sealed     BLOB    NOT NULL,    -- nonce || ciphertext
    created_at INTEGER NOT NULL,
    _hlc       INTEGER NOT NULL DEFAULT 0,
    _origin    TEXT    NOT NULL DEFAULT '',
    _deleted   INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
) STRICT;

-- +goose Down
DROP TABLE audit_keys;
DROP INDEX audit_log_sealed_ts;
DROP INDEX audit_log_chain;
ALTER TABLE audit_log DROP COLUMN chain_mac;
ALTER TABLE audit_log DROP COLUMN chain_kid;
ALTER TABLE audit_log DROP COLUMN chain_prev;
ALTER TABLE audit_log DROP COLUMN chain_seq;
ALTER TABLE audit_log DROP COLUMN chain_origin;
