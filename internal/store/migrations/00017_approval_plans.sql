-- SPDX-License-Identifier: AGPL-3.0-only
-- A decided approval keeps no plan: the plan can hold secrets from command
-- arguments. DecideApproval now clears it in the write that records the
-- decision; this clears it from the approvals decided before.

-- +goose Up
UPDATE approvals SET detail = json_remove(detail, '$.plan') WHERE status != 'pending';

-- +goose Down
-- The cleared plans are gone; there is nothing to restore.
SELECT 1;
