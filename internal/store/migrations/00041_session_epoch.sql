-- SPDX-License-Identifier: AGPL-3.0-only
-- Grants on masters only (#384).
--
-- Session epochs: a password reset raises admin.session_epoch; a session
-- keeps the epoch it was created under, and one older than the admin row's
-- is ended, on every master, whichever sessions it holds.
--
-- The sessions, MCP and dashboard tokens and panel links of a database that
-- was a cluster's (it holds the hub certificates of more than one hub) are
-- deleted: before, their rows lived on the storage members a key placed
-- them on, so a master's copy may lack a sign-out or a revocation, and from
-- now on a master trusts its own copy. A single hub's are kept. This runs
-- once per database, a restored archive's too.

-- +goose Up
ALTER TABLE admin ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;

DELETE FROM panel_links WHERE (SELECT count(DISTINCT node_id) FROM hub_certs) > 1;
DELETE FROM sessions WHERE (SELECT count(DISTINCT node_id) FROM hub_certs) > 1;
DELETE FROM mcp_tokens WHERE (SELECT count(DISTINCT node_id) FROM hub_certs) > 1;
DELETE FROM dashboard_tokens WHERE (SELECT count(DISTINCT node_id) FROM hub_certs) > 1;

-- +goose Down
ALTER TABLE sessions DROP COLUMN epoch;
ALTER TABLE admin DROP COLUMN session_epoch;
