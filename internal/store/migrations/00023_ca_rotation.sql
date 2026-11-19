-- SPDX-License-Identifier: AGPL-3.0-only
-- Hub CA rotation (docs/cluster.md, "Rotating the hub CA").
--
-- fingerprint is the SHA-256 of a certificate's DER encoding, lowercase hex
-- (pki.FingerprintHex), and ca_fp that of the CA certificate that issued it.
-- Both are NULL for a certificate recorded before this migration; a device's
-- fingerprint is then pinned on its next connect (trust on first use). A
-- rotation renews only certificates whose exact fingerprint is pinned: their
-- serials and IDs are no secret to whoever holds a copy of the database.
--
-- ca_rotations has a row per rotation, the one with finished_at NULL in
-- progress. new_cert is the new CA certificate (public); its private key is
-- never stored here, but fetched by each member over the pinned cluster
-- channel. pins are the hub node certificates the leader saw each member
-- present when the rotation started, as a JSON object of node ID to a list of
-- fingerprints: the only old-CA hub certificates accepted until it finishes.

-- +goose Up
ALTER TABLE certs ADD COLUMN fingerprint TEXT;
ALTER TABLE certs ADD COLUMN ca_fp TEXT;
ALTER TABLE hub_certs ADD COLUMN fingerprint TEXT;
ALTER TABLE hub_certs ADD COLUMN ca_fp TEXT;

CREATE TABLE ca_rotations (
    new_fp      TEXT    PRIMARY KEY,
    old_fp      TEXT    NOT NULL,
    new_cert    BLOB    NOT NULL,
    pins        TEXT    NOT NULL,
    stage       TEXT    NOT NULL CHECK (stage IN ('started', 'cutover', 'finished')),
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
) STRICT;

-- +goose Down
DROP TABLE ca_rotations;
ALTER TABLE hub_certs DROP COLUMN ca_fp;
ALTER TABLE hub_certs DROP COLUMN fingerprint;
ALTER TABLE certs DROP COLUMN ca_fp;
ALTER TABLE certs DROP COLUMN fingerprint;
