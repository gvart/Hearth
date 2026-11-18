# Kubernetes clusters

Hearth adopts an existing Kubernetes cluster (Talos, k3s, kind, ...) through a kubeconfig. Nothing is
installed in the cluster and Hearth only reads from it: nodes, namespaces, workloads (Deployments,
StatefulSets, DaemonSets), pods with their status, events, and pod logs.

## Adding a cluster

In the UI, open **Kubernetes** and **Add cluster**, then paste a kubeconfig or load the file:

| Distribution | Kubeconfig                                                   |
| ------------ | ------------------------------------------------------------ |
| Talos        | `talosctl kubeconfig -` (prints it)                          |
| k3s          | `/etc/rancher/k3s/k3s.yaml`; replace `127.0.0.1` in `server` |
| kind         | `kind get kubeconfig --name <cluster>`                       |

Only the kubeconfig's **current context** is used and kept. It must authenticate with a client
certificate, a bearer token or a username and password. Certificate, key and CA files named by an
absolute path are read on the hub when the cluster is added and stored inline, so every hub of a cluster
can use them. Refused, with an explanation:

- `exec` and `auth-provider` credential plugins (cloud CLIs, OIDC helpers): they would run programs on
  the hub;
- `tokenFile`: it would send a file of the hub host to the API server.

Use a service account token or a client certificate for those clusters instead. The kubeconfig grants
whatever its user may do; Hearth itself never writes to the cluster, so a read-only role is enough
(`get`, `list`, `watch` on nodes, namespaces, pods, events and the apps workloads, and `get` on
`pods/log`).

## How it works

- **Stored encrypted.** The kubeconfig is sealed with AES-256-GCM before it reaches the database, so
  the database, the Raft log and snapshots only ever hold ciphertext. The key is derived (HKDF-SHA256)
  from the hub CA's private key, which every hub of a cluster already holds in its data dir (0600).
  Rotating the CA ([#84](https://github.com/gvart/hearth/issues/84)) will have to reseal them.
- **Watch, not poll.** The hub lists each resource once and then watches it. Changes reach the UI over
  the same live event stream as device changes, typically within a fraction of a second. A watch that
  falls too far behind lists again.
- **Every hub watches.** In a hub cluster each hub watches every Kubernetes cluster itself and serves
  its own UI from its own cache. Kubernetes state is never written to the hub database: it is a cache
  of the API server, and replicating it through Raft would flood the log. Adding or removing a cluster
  is replicated like any other write; the other hubs start or stop their watch within 5 seconds.
- **Nodes and devices.** A node is linked to the Hearth device it runs on when one of the node's
  addresses is one of the device's addresses, or failing that, when the node's hostname or name matches
  the device's hostname. A match that is not unique links nothing.
- **Pod logs** are read on demand (the last 100 to 2000 lines), not streamed.

Adding and removing a cluster (`kube.cluster.add`, `kube.cluster.remove`, both safe) and reading pod
logs (`kube.pod.logs`, read: logs may hold secrets) are policy actions, decided and audited like every
other action. The kubeconfig never appears in the audit log, the hub log or the API.

On a hub cluster upgraded from an older version, run `hearth cluster migrate` before adding a cluster
(the table arrives with schema 8).
