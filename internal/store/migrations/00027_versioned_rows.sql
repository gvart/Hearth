-- SPDX-License-Identifier: AGPL-3.0-only
-- Versioned rows (docs/design/ap-cluster.md §4). Every replicated row carries
-- the version of the write that made it: _hlc, a hybrid logical clock
-- timestamp (internal/hlc), and _origin, the member that stamped it. Two
-- versions of a row merge last-writer-wins on (_hlc, _origin). _deleted
-- marks a tombstone: a deleted row kept, without its secrets, so that an
-- older write arriving later cannot bring it back; reads skip tombstones and
-- they are dropped after a GC window. Rows written before this migration are
-- at version (0, '').
--
-- The audit log is append-only and never merged: _hlc, _origin and _seq are
-- its global id across members, and the log lists in that order. Entries
-- written before this migration have no HLC: _seq is their id, so they keep
-- their order, before every newer entry. id stays the local row id.

-- +goose Up
ALTER TABLE devices ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE tokens ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tokens ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE tokens ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE certs ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE certs ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE admin ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admin ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE admin ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE sessions ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE join_tokens ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE join_tokens ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE join_tokens ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE cluster_hubs ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cluster_hubs ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE cluster_hubs ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE hub_certs ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hub_certs ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE hub_certs ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE automation_runs ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE automation_runs ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE automation_runs ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE kube_clusters ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE kube_clusters ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE kube_clusters ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE approvals ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE approvals ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE approvals ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE approval_links ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE approval_links ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_links ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE mcp_tokens ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mcp_tokens ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE mcp_tokens ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE network_hosts ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE network_hosts ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE network_hosts ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE proxmox_servers ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxmox_servers ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE proxmox_servers ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE runbook_runs ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runbook_runs ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE runbook_runs ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE telemetry ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE panels ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panels ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE panels ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE panel_links ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_links ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE panel_links ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE dashboard_tokens ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dashboard_tokens ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE dashboard_tokens ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE ca_rotations ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ca_rotations ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE ca_rotations ADD COLUMN _deleted INTEGER NOT NULL DEFAULT 0 CHECK (_deleted IN (0, 1));

ALTER TABLE audit_log ADD COLUMN _hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_log ADD COLUMN _origin TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN _seq INTEGER NOT NULL DEFAULT 0;

-- The backfill is an update the log takes once, as in 00018: lift the guard
-- around it.
DROP TRIGGER audit_log_no_update;

UPDATE audit_log SET _seq = id;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

-- The global id is unique by construction (see store.Merge); the index
-- orders the log and finds an entry by it.
CREATE INDEX audit_log_global ON audit_log (_hlc, _origin, _seq);

-- +goose Down
DROP INDEX audit_log_global;
ALTER TABLE audit_log DROP COLUMN _seq;
ALTER TABLE audit_log DROP COLUMN _origin;
ALTER TABLE audit_log DROP COLUMN _hlc;
ALTER TABLE ca_rotations DROP COLUMN _deleted;
ALTER TABLE ca_rotations DROP COLUMN _origin;
ALTER TABLE ca_rotations DROP COLUMN _hlc;
ALTER TABLE dashboard_tokens DROP COLUMN _deleted;
ALTER TABLE dashboard_tokens DROP COLUMN _origin;
ALTER TABLE dashboard_tokens DROP COLUMN _hlc;
ALTER TABLE panel_links DROP COLUMN _deleted;
ALTER TABLE panel_links DROP COLUMN _origin;
ALTER TABLE panel_links DROP COLUMN _hlc;
ALTER TABLE panels DROP COLUMN _deleted;
ALTER TABLE panels DROP COLUMN _origin;
ALTER TABLE panels DROP COLUMN _hlc;
ALTER TABLE telemetry DROP COLUMN _deleted;
ALTER TABLE telemetry DROP COLUMN _origin;
ALTER TABLE telemetry DROP COLUMN _hlc;
ALTER TABLE runbook_runs DROP COLUMN _deleted;
ALTER TABLE runbook_runs DROP COLUMN _origin;
ALTER TABLE runbook_runs DROP COLUMN _hlc;
ALTER TABLE proxmox_servers DROP COLUMN _deleted;
ALTER TABLE proxmox_servers DROP COLUMN _origin;
ALTER TABLE proxmox_servers DROP COLUMN _hlc;
ALTER TABLE network_hosts DROP COLUMN _deleted;
ALTER TABLE network_hosts DROP COLUMN _origin;
ALTER TABLE network_hosts DROP COLUMN _hlc;
ALTER TABLE mcp_tokens DROP COLUMN _deleted;
ALTER TABLE mcp_tokens DROP COLUMN _origin;
ALTER TABLE mcp_tokens DROP COLUMN _hlc;
ALTER TABLE approval_links DROP COLUMN _deleted;
ALTER TABLE approval_links DROP COLUMN _origin;
ALTER TABLE approval_links DROP COLUMN _hlc;
ALTER TABLE approvals DROP COLUMN _deleted;
ALTER TABLE approvals DROP COLUMN _origin;
ALTER TABLE approvals DROP COLUMN _hlc;
ALTER TABLE kube_clusters DROP COLUMN _deleted;
ALTER TABLE kube_clusters DROP COLUMN _origin;
ALTER TABLE kube_clusters DROP COLUMN _hlc;
ALTER TABLE automation_runs DROP COLUMN _deleted;
ALTER TABLE automation_runs DROP COLUMN _origin;
ALTER TABLE automation_runs DROP COLUMN _hlc;
ALTER TABLE hub_certs DROP COLUMN _deleted;
ALTER TABLE hub_certs DROP COLUMN _origin;
ALTER TABLE hub_certs DROP COLUMN _hlc;
ALTER TABLE cluster_hubs DROP COLUMN _deleted;
ALTER TABLE cluster_hubs DROP COLUMN _origin;
ALTER TABLE cluster_hubs DROP COLUMN _hlc;
ALTER TABLE join_tokens DROP COLUMN _deleted;
ALTER TABLE join_tokens DROP COLUMN _origin;
ALTER TABLE join_tokens DROP COLUMN _hlc;
ALTER TABLE sessions DROP COLUMN _deleted;
ALTER TABLE sessions DROP COLUMN _origin;
ALTER TABLE sessions DROP COLUMN _hlc;
ALTER TABLE admin DROP COLUMN _deleted;
ALTER TABLE admin DROP COLUMN _origin;
ALTER TABLE admin DROP COLUMN _hlc;
ALTER TABLE certs DROP COLUMN _deleted;
ALTER TABLE certs DROP COLUMN _origin;
ALTER TABLE certs DROP COLUMN _hlc;
ALTER TABLE tokens DROP COLUMN _deleted;
ALTER TABLE tokens DROP COLUMN _origin;
ALTER TABLE tokens DROP COLUMN _hlc;
ALTER TABLE devices DROP COLUMN _deleted;
ALTER TABLE devices DROP COLUMN _origin;
ALTER TABLE devices DROP COLUMN _hlc;
