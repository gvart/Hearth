-- SPDX-License-Identifier: AGPL-3.0-only
-- The network edges each device's agent last reported (docs/net-edges.md):
-- its neighbour table entries (kind 'neighbor', with the peer's MAC) and its
-- established TCP connections grouped by peer, port and direction (kind
-- 'connection'). An agent's report replaces all of its device's rows.
-- updated_at is when the device's set of edges last changed (unix ms).

-- +goose Up
CREATE TABLE net_edges (
    device_id  TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('neighbor', 'connection')),
    ip         TEXT    NOT NULL,
    mac        TEXT    NOT NULL DEFAULT '',
    port       INTEGER NOT NULL DEFAULT 0,
    inbound    INTEGER NOT NULL DEFAULT 0 CHECK (inbound IN (0, 1)),
    count      INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, kind, ip, port, inbound)
) STRICT;

-- +goose Down
DROP TABLE net_edges;
