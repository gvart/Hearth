-- SPDX-License-Identifier: AGPL-3.0-only
-- Auto hubs (#328). An enrollment token may let the device that redeems it
-- become a hub: hub_roles are the cluster roles it may be offered,
-- comma-separated; empty offers none. A join token the hub mints for such a
-- device names it in device_id; empty for one an admin created.

-- +goose Up
ALTER TABLE tokens ADD COLUMN hub_roles TEXT NOT NULL DEFAULT '';
ALTER TABLE join_tokens ADD COLUMN device_id TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE join_tokens DROP COLUMN device_id;
ALTER TABLE tokens DROP COLUMN hub_roles;
