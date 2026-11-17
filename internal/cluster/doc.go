// SPDX-License-Identifier: AGPL-3.0-only

// Package cluster replicates the hub store across 3 or 5 hubs with Raft
// (hashicorp/raft, log and stable store in bbolt under <data-dir>/raft).
//
// The state machine is the store itself: every node decodes each committed
// log entry with store.DecodeCommand and applies it with Store.ApplyLocal, and
// raft snapshots are Store.Snapshot / Store.Restore. A Node is the store's
// Applier: on the leader it proposes the encoded command and returns what the
// state machine returned; on a follower Apply fails with *ErrNotLeader, and
// ApplyOrForward (what a hub binds with BindForwarding) sends the command to
// the leader's ClusterService.Forward instead.
//
// Hubs talk Raft over TCP with mutual TLS. Every node presents a hub node
// certificate issued by the hub CA (URI SAN urn:hearth:hub:<node-id>) and
// accepts only peers with one, so an enrolled device's certificate cannot
// join the transport.
//
// A cluster forms from an existing hub: its first clustered start bootstraps a
// one-voter configuration from a snapshot of its current database. New hubs
// join through ClusterService on the leader's TLS listener with a single-use
// join token, receive a node certificate and the CA (key included) over the
// pinned channel, are added as non-voters, catch up through a snapshot and
// then ask to be promoted to voters.
package cluster
