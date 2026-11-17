-- SPDX-License-Identifier: AGPL-3.0-only
-- Device boot time, derived by the hub from heartbeat uptime. INTEGER unix
-- milliseconds (UTC); NULL while unknown.

-- +goose Up
ALTER TABLE devices ADD COLUMN boot_time INTEGER;

-- +goose Down
ALTER TABLE devices DROP COLUMN boot_time;
