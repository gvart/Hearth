-- SPDX-License-Identifier: AGPL-3.0-only
-- Capabilities managed from the hub (#346). device_ceilings holds, per
-- device, the capability ceiling the hub sets for its agent: protojson of a
-- hearth.agent.v1.Ceiling. The agent adds it to its own flags unless it runs
-- with --local-ceiling. A row of its own, not a column of devices, which
-- every heartbeat rewrites.

-- +goose Up
CREATE TABLE device_ceilings (
    device_id  TEXT    PRIMARY KEY,
    ceiling    TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL DEFAULT '',
    _hlc       INTEGER NOT NULL DEFAULT 0,
    _origin    TEXT    NOT NULL DEFAULT '',
    _deleted   INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
) STRICT;

-- +goose Down
DROP TABLE device_ceilings;
