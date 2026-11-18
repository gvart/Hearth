-- SPDX-License-Identifier: AGPL-3.0-only
-- Hosts found by network discovery (ARP sweep, mDNS), keyed by MAC address so
-- a host that moves to another IP stays one row. A host whose MAC is one of
-- an enrolled device's interfaces is that device; the rest are unmanaged.

-- +goose Up
CREATE TABLE network_hosts (
    mac        TEXT    PRIMARY KEY, -- lower-case, colon-separated
    ip         TEXT    NOT NULL,    -- the address it last answered on
    hostname   TEXT    NOT NULL DEFAULT '',
    vendor     TEXT    NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE network_hosts;
