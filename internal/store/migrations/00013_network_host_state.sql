-- SPDX-License-Identifier: AGPL-3.0-only
-- What the operator said about a host network discovery found: '' not yet
-- reviewed, 'known' (theirs) or 'ignored' (not worth hearing about). Known
-- and ignored hosts never fire new-device alerts.

-- +goose Up
ALTER TABLE network_hosts ADD COLUMN state TEXT NOT NULL DEFAULT ''
    CHECK (state IN ('', 'known', 'ignored'));

-- +goose Down
ALTER TABLE network_hosts DROP COLUMN state;
