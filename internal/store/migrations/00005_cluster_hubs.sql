-- SPDX-License-Identifier: AGPL-3.0-only
-- The agent-facing URL of every hub in a Raft cluster, keyed by Raft node ID.
-- Each hub writes its own row; Raft itself only knows hub-to-hub addresses.

-- +goose Up
CREATE TABLE cluster_hubs (
    node_id   TEXT PRIMARY KEY,
    agent_url TEXT NOT NULL
) STRICT;

-- +goose Down
DROP TABLE cluster_hubs;
