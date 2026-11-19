-- SPDX-License-Identifier: AGPL-3.0-only
-- Guest and kiosk panels (docs/panels.md). A panel is a name and an ordered
-- list of widgets, kept as the JSON the hub validated: each widget points at
-- one entity and lists the actions a guest may take on it. A share link opens
-- one panel without a login; only the SHA-256 hash of its secret is stored.
-- expires_at and revoked_at are unix ms, NULL for never and not revoked.

-- +goose Up
CREATE TABLE panels (
    id         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL,
    widgets    TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE panel_links (
    id         TEXT    PRIMARY KEY,
    panel_id   TEXT    NOT NULL REFERENCES panels (id) ON DELETE CASCADE,
    hash       BLOB    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
) STRICT;

CREATE INDEX panel_links_panel ON panel_links (panel_id);

-- +goose Down
DROP TABLE panel_links;
DROP TABLE panels;
