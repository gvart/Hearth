-- SPDX-License-Identifier: AGPL-3.0-only
-- Which scanner last found each network host: '' for the hub, or the id of the
-- device whose agent swept the host's subnet (a subnet the hub is not attached
-- to). Hosts stored before this migration were found by the hub.

-- +goose Up
ALTER TABLE network_hosts ADD COLUMN scanned_by TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE network_hosts DROP COLUMN scanned_by;
