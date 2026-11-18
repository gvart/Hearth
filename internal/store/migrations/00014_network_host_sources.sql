-- SPDX-License-Identifier: AGPL-3.0-only
-- Where each network host was learned: the ARP scan, Pi-hole, DHCP lease
-- files (sources, a sorted comma-separated set), and which of them gave its
-- hostname (hostname_source), so a scan does not replace a name Pi-hole or a
-- DHCP lease gave. last_scan is when a scan last found the host, 0 if none
-- has: last_seen also moves with imports, and a host counts as returned only
-- by scans. Hosts stored before this migration came from scans.

-- +goose Up
ALTER TABLE network_hosts ADD COLUMN sources TEXT NOT NULL DEFAULT '';
ALTER TABLE network_hosts ADD COLUMN hostname_source TEXT NOT NULL DEFAULT '';
ALTER TABLE network_hosts ADD COLUMN last_scan INTEGER NOT NULL DEFAULT 0;
UPDATE network_hosts SET sources = 'scan', last_scan = last_seen,
    hostname_source = CASE WHEN hostname != '' THEN 'scan' ELSE '' END;

-- +goose Down
ALTER TABLE network_hosts DROP COLUMN last_scan;
ALTER TABLE network_hosts DROP COLUMN hostname_source;
ALTER TABLE network_hosts DROP COLUMN sources;
