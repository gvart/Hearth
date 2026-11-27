-- SPDX-License-Identifier: AGPL-3.0-only
-- Exec plugins for devices (#223). device_plugins holds, per plugin and
-- platform (Go's os and arch), the plugin uploaded for the agents of that
-- platform: its version, the SHA-256 and size of its program, and its
-- manifest (JSON: args, capabilities, commands with their classes; never an
-- env). The program itself is not in the store: it is a file in the data dir
-- of the hub named by holder, which other hubs fetch it from.

-- +goose Up
CREATE TABLE device_plugins (
    id          TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    os          TEXT    NOT NULL,
    arch        TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    manifest    TEXT    NOT NULL,
    holder      TEXT    NOT NULL DEFAULT '',
    uploaded_at INTEGER NOT NULL,
    uploaded_by TEXT    NOT NULL DEFAULT '',
    _hlc        INTEGER NOT NULL DEFAULT 0,
    _origin     TEXT    NOT NULL DEFAULT '',
    _deleted    INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1))
) STRICT;

-- +goose Down
DROP TABLE device_plugins;
