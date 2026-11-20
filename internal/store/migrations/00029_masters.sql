-- SPDX-License-Identifier: AGPL-3.0-only
-- Masters of an AP cluster (docs/design/ap-cluster.md §6).
--
-- owner is the hub node id of the master that created an enrollment token,
-- a join token, an approval or an approval link: only that master consumes
-- or decides it. It is empty on a single hub and in a Raft cluster, where
-- any hub may.
--
-- device_routes says which master holds each device's agent stream, so a
-- call that needs the stream is forwarded there from another master. It is
-- soft state: written by the master a stream reaches, never cleared, and
-- believed only while that master is alive.

-- +goose Up
ALTER TABLE tokens ADD COLUMN owner TEXT NOT NULL DEFAULT '';
ALTER TABLE join_tokens ADD COLUMN owner TEXT NOT NULL DEFAULT '';
ALTER TABLE approvals ADD COLUMN owner TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_links ADD COLUMN owner TEXT NOT NULL DEFAULT '';
CREATE TABLE device_routes (
    device_id TEXT    PRIMARY KEY,
    master    TEXT    NOT NULL,
    at        INTEGER NOT NULL,
    _hlc      INTEGER NOT NULL DEFAULT 0,
    _origin   TEXT    NOT NULL DEFAULT '',
    _deleted  INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
) STRICT;

-- +goose Down
DROP TABLE device_routes;
ALTER TABLE approval_links DROP COLUMN owner;
ALTER TABLE approvals DROP COLUMN owner;
ALTER TABLE join_tokens DROP COLUMN owner;
ALTER TABLE tokens DROP COLUMN owner;
