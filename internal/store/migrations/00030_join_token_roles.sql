-- SPDX-License-Identifier: AGPL-3.0-only
-- The cluster roles a join token grants (#273): a comma-separated subset of
-- storage and master, picked by the admin who created it. A hub that joins
-- with the token takes at most these roles, and receives the CA key only
-- when they include master. Empty grants none: such a token admits no hub.

-- +goose Up
ALTER TABLE join_tokens ADD COLUMN roles TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE join_tokens DROP COLUMN roles;
