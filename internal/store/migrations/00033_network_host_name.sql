-- SPDX-License-Identifier: AGPL-3.0-only
-- Hosts adopted as agentless devices (#313): the state 'adopted', and the name
-- the operator gave the host ('' for a host not adopted). SQLite cannot change
-- a CHECK, so state is rebuilt as a new column with the wider one.

-- +goose Up
ALTER TABLE network_hosts ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE network_hosts ADD COLUMN state_new TEXT NOT NULL DEFAULT ''
    CHECK (state_new IN ('', 'known', 'ignored', 'adopted'));
UPDATE network_hosts SET state_new = state;
ALTER TABLE network_hosts DROP COLUMN state;
ALTER TABLE network_hosts RENAME COLUMN state_new TO state;

-- +goose Down
ALTER TABLE network_hosts ADD COLUMN state_old TEXT NOT NULL DEFAULT ''
    CHECK (state_old IN ('', 'known', 'ignored'));
UPDATE network_hosts SET state_old = CASE WHEN state = 'adopted' THEN '' ELSE state END;
ALTER TABLE network_hosts DROP COLUMN state;
ALTER TABLE network_hosts RENAME COLUMN state_old TO state;
ALTER TABLE network_hosts DROP COLUMN name;
