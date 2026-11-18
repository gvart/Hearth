// SPDX-License-Identifier: AGPL-3.0-only

// Package kubernetes adopts existing Kubernetes clusters through a
// kubeconfig, read-only and without installing anything in them. It keeps
// an informer cache of each cluster's nodes, namespaces, workloads, pods and
// events, streams their changes, reads pod logs, and links nodes to the
// Hearth devices they run on. Kubeconfigs are stored sealed (see Sealer).
package kubernetes
