-- SPDX-License-Identifier: AGPL-3.0-only
-- Hub node certificates of a Raft cluster, by serial, and their revocation.
-- Kept apart from device certs: those rows belong to a device (a foreign key
-- that cascades), hub certificates to a Raft node ID. Removing a hub from the
-- cluster revokes every serial recorded for its node ID.

-- +goose Up
CREATE TABLE hub_certs (
    serial     TEXT    PRIMARY KEY, -- lowercase hex, as pki.SerialString
    node_id    TEXT    NOT NULL,
    revoked_at INTEGER
) STRICT;

CREATE INDEX hub_certs_node_id ON hub_certs (node_id);

-- +goose Down
DROP TABLE hub_certs;
