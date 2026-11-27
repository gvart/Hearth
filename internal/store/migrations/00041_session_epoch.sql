-- SPDX-License-Identifier: AGPL-3.0-only
-- Session epochs (#384). A password reset raises admin.session_epoch; a
-- session keeps the epoch it was created under, and one older than the
-- admin row's is ended, on every master, whichever sessions it holds.

-- +goose Up
ALTER TABLE admin ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE sessions DROP COLUMN epoch;
ALTER TABLE admin DROP COLUMN session_epoch;
