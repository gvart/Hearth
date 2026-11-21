// SPDX-License-Identifier: AGPL-3.0-only

// Package cluster runs every hub as a member of a leaderless (AP) cluster; a
// hub alone is a cluster of one (docs/cluster.md).
//
// Members find each other by memberlist gossip (Membership) and take roles:
// storage members hold the store's rows, sharded on a ring of N copies
// (Replicator: last-writer-wins by HLC, hints and anti-entropy), and masters
// serve the API, UI and agents and hold the CA key. Gossip and replication
// share one TCP port, --cluster-listen, over mutual TLS: every member
// presents a hub node certificate issued by the hub CA (URI SAN
// urn:hearth:hub:<node-id>) and accepts only peers with one, so an enrolled
// device's certificate cannot join.
//
// A hub joins through ClusterService on a master's TLS listener with a
// single-use join token, and receives a node certificate and the CA (the key
// only if it allows the master role) over the pinned channel.
package cluster
