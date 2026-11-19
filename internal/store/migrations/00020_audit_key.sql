-- SPDX-License-Identifier: AGPL-3.0-only
-- An audit entry a hub could not write at once (a cluster without quorum)
-- is written again later, maybe after the first write committed after all.
-- The key the entry carries on every attempt lands it once: a write whose key
-- is in the log already adds nothing. Entries written in one go carry none.
--
-- The key's unique index is a second conflict target for INSERT OR REPLACE,
-- which would delete the row holding the key: the guard against a REPLACE
-- (00019) refuses an insert of an existing key too.

-- +goose Up
ALTER TABLE audit_log ADD COLUMN audit_key TEXT;

CREATE UNIQUE INDEX audit_log_key ON audit_log (audit_key) WHERE audit_key IS NOT NULL;

DROP TRIGGER audit_log_no_replace;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_replace BEFORE INSERT ON audit_log
WHEN (NEW.id IS NOT NULL AND EXISTS (SELECT 1 FROM audit_log WHERE id = NEW.id))
  OR (NEW.audit_key IS NOT NULL AND EXISTS (SELECT 1 FROM audit_log WHERE audit_key = NEW.audit_key))
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER audit_log_no_replace;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_replace BEFORE INSERT ON audit_log
WHEN NEW.id IS NOT NULL AND EXISTS (SELECT 1 FROM audit_log WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

DROP INDEX audit_log_key;
ALTER TABLE audit_log DROP COLUMN audit_key;
