-- SPDX-License-Identifier: AGPL-3.0-only
-- What a host tells about itself, for its kind (#311): the mDNS service types
-- it answers for (a JSON array, '' for none) and whether it is a default
-- gateway of the scanner that found it.

-- +goose Up
ALTER TABLE network_hosts ADD COLUMN services TEXT NOT NULL DEFAULT '';
ALTER TABLE network_hosts ADD COLUMN gateway INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE network_hosts DROP COLUMN gateway;
ALTER TABLE network_hosts DROP COLUMN services;
