-- SPDX-License-Identifier: AGPL-3.0-only
-- An audit entry a hub could not write at once (a cluster without quorum)
-- is written again later, maybe after the first write committed after all.
-- The key the entry carries on every attempt lands it once: a write whose key
-- is in the log already adds nothing. Entries written in one go carry none.

-- +goose Up
ALTER TABLE audit_log ADD COLUMN audit_key TEXT;

CREATE UNIQUE INDEX audit_log_key ON audit_log (audit_key) WHERE audit_key IS NOT NULL;

-- +goose Down
DROP INDEX audit_log_key;
ALTER TABLE audit_log DROP COLUMN audit_key;
