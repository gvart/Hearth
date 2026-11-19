-- SPDX-License-Identifier: AGPL-3.0-only
-- Hub CA rotations (#84). A rotation is started on the leader, which writes
-- the next CA's certificate here; its key never reaches the store, the Raft
-- log or a snapshot: each member fetches it from the leader over the pinned
-- cluster channel.
--
-- pins is a JSON object: hub node ID -> fingerprint of the node certificate
-- that hub presented on a connection the leader dialed when it started the
-- rotation. Until the rotation finishes, a hub presenting a certificate of
-- the old CA is accepted only with exactly that certificate.
--
-- stage is started (both CAs trusted, the old one served), cutover (the new
-- one served) or finished (the old one dropped, its key deleted).

-- +goose Up
CREATE TABLE ca_rotations (
    new_ca_fp   TEXT    PRIMARY KEY,
    old_ca_fp   TEXT    NOT NULL,
    new_ca_cert TEXT    NOT NULL,
    pins        TEXT    NOT NULL,
    stage       TEXT    NOT NULL,
    started_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE ca_rotations;
