-- SPDX-License-Identifier: AGPL-3.0-only
-- The device name an enrollment token gives (#312): the device that enrolls
-- with the token takes it instead of its hostname. Empty names none.

-- +goose Up
ALTER TABLE tokens ADD COLUMN name TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE tokens DROP COLUMN name;
