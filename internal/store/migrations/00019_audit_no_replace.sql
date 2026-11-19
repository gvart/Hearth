-- SPDX-License-Identifier: AGPL-3.0-only
-- INSERT OR REPLACE (and REPLACE INTO) on an existing audit id deletes the old
-- row without firing the delete trigger, which rewrites the log. A BEFORE
-- INSERT trigger runs before the conflict is resolved, so it refuses the
-- insert first. Hearth only ever appends with a plain INSERT.

-- +goose Up
-- +goose StatementBegin
CREATE TRIGGER audit_log_no_replace BEFORE INSERT ON audit_log
WHEN NEW.id IS NOT NULL AND EXISTS (SELECT 1 FROM audit_log WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER audit_log_no_replace;
