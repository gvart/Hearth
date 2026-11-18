-- SPDX-License-Identifier: AGPL-3.0-only
-- Kubernetes clusters adopted through a kubeconfig. The kubeconfig is sealed
-- (AES-256-GCM) before it reaches the store, so neither this table, the Raft
-- log nor a snapshot ever holds it in the clear.

-- +goose Up
CREATE TABLE kube_clusters (
    id         TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    kubeconfig BLOB    NOT NULL, -- sealed: nonce || ciphertext
    created_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE kube_clusters;
