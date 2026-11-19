-- SPDX-License-Identifier: AGPL-3.0-only
-- The operation id that ties an audit entry written before an action to the
-- entry reporting its outcome moves out of the detail JSON into columns, so
-- paging the log does not parse the detail of every row it scans. Columns are
-- ANY so a value keeps the type it has in the detail, and the folding reads
-- the same as it did from json_extract.

-- +goose Up
ALTER TABLE audit_log ADD COLUMN audit_op ANY;
ALTER TABLE audit_log ADD COLUMN audit_outcome_of ANY;

CREATE INDEX audit_log_outcome_of ON audit_log (audit_outcome_of);

-- The backfill is the one update the log ever takes: lift the guard around it.
DROP TRIGGER audit_log_no_update;

UPDATE audit_log SET
    audit_op = json_extract(detail, '$.audit_op'),
    audit_outcome_of = json_extract(detail, '$.audit_outcome_of')
WHERE json_valid(detail);

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP INDEX audit_log_outcome_of;
ALTER TABLE audit_log DROP COLUMN audit_outcome_of;
ALTER TABLE audit_log DROP COLUMN audit_op;
