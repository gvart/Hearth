// SPDX-License-Identifier: AGPL-3.0-only

// Package kubernetes adopts existing Kubernetes clusters through a
// kubeconfig, read-only and without installing anything in them. It lists and
// watches each cluster's nodes, namespaces, workloads, pods and events
// into a cache, streams their changes, reads pod logs, and links nodes to the
// Hearth devices they run on. Kubeconfigs are stored sealed (see Sealer).
package kubernetes
