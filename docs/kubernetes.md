---
title: Kubernetes
description: Adopt a Kubernetes cluster through a kubeconfig, watch it and take day-two actions.
---

Hearth adopts an existing Kubernetes cluster (Talos, k3s, kind, ...) through a kubeconfig. Nothing is
installed in the cluster. Hearth reads nodes, namespaces, workloads (Deployments, StatefulSets,
DaemonSets), pods with their status, events, and pod logs, and writes only when you take one of a few
[actions](#actions): restart, scale, delete a pod, cordon, uncordon, drain.

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
whatever its user may do. A read-only role is enough to watch (`get`, `list`, `watch` on nodes,
namespaces, pods, events and the apps workloads, and `get` on `pods/log`); the actions also need
`patch` on the apps workloads, `deployments/scale`, `statefulsets/scale` and nodes, `delete` on pods and
`create` on `pods/eviction`. Without them an action fails with the API server's "forbidden" and nothing
changes.

## How it works

- **Stored encrypted.** The kubeconfig is sealed with AES-256-GCM before it reaches the database, so
  the database, the replication between hubs and snapshots only ever hold ciphertext. The key is derived
  (HKDF-SHA256) from the hub CA's private key, which every master of a cluster already holds in its data
  dir (0600).
  Rotating the CA ([#84](https://github.com/gvart/hearth/issues/84)) will have to reseal them.
- **Watch, not poll.** The hub lists each resource once and then watches it. Changes reach the UI over
  the same live event stream as device changes, typically within a fraction of a second. A watch that
  falls too far behind lists again.
- **Every master watches.** In a hub cluster each master watches every Kubernetes cluster itself and
  serves its own UI from its own cache. Kubernetes state is never written to the hub database: it is a
  cache of the API server, and replicating it would flood the cluster. Adding or removing a cluster is
  replicated like any other write; the other masters start or stop their watch within 5 seconds.
- **Nodes and devices.** A node is linked to the Hearth device it runs on when one of the node's
  addresses is one of the device's addresses, or failing that, when the node's hostname or name matches
  the device's hostname. A match that is not unique links nothing. Nodes that cannot run a host
  agent, such as Talos nodes, become devices through the agent DaemonSet (see [talos.md](talos.md)).
- **Pod logs** are read on demand (the last 100 to 2000 lines), not streamed, in the same viewer as
  device logs (see [logs.md](logs.md)).

Adding and removing a cluster (`kube.cluster.add`, `kube.cluster.remove`, both safe) and reading pod
logs (`kube.pod.logs`, read: logs may hold secrets) are policy actions, decided and audited like every
other action. The kubeconfig never appears in the audit log, the hub log or the API.

## Actions

Deploys stay with your GitOps tool (Argo CD, Flux); Hearth has the few day-two actions a homelab needs.
They are buttons on the Kubernetes page, `POST /api/v1/kube/clusters/{id}/actions`, and the
`kube_*` [automation actions](automations.md#kubernetes-actions):

| Action                                    | Policy action           | Class     | What it does                                                                |
| ----------------------------------------- | ----------------------- | --------- | --------------------------------------------------------------------------- |
| Restart a Deployment, StatefulSet or DaemonSet | `kube.workload.restart` | safe      | A rolling restart, as `kubectl rollout restart` (the `restartedAt` annotation) |
| Scale a Deployment or StatefulSet         | `kube.workload.scale`   | safe      | Sets the replicas through the `scale` subresource                           |
| Delete a pod                              | `kube.pod.delete`       | safe      | Deletes it with its grace period; its controller, if any, recreates it      |
| Cordon, uncordon a node                   | `kube.node.cordon`, `kube.node.uncordon` | safe | Sets `spec.unschedulable`                                     |
| Drain a node                              | `kube.node.drain`       | dangerous | Cordons it and evicts its pods (below)                                      |

Automations and runbooks also have `kube_node_delete` (`kube.node.delete`, dangerous), which deletes a
Node object, and runbooks a `kube_node` check (`kube.node.ready`, read) that passes when a node is Ready:
see [automations](automations.md#kubernetes-actions) and [runbooks](runbooks.md#steps). Neither is a
button on the Kubernetes page.

- **Dry run first.** Every action can be planned with `"dry_run": true`: Hearth reads the objects
  involved and says what the action would do, with warnings (a pod no controller recreates, a
  `Recreate` strategy, scaling to zero, ...). The UI always shows the dry run and asks to confirm. A dry
  run changes nothing; policy decides on it and audits it with the result `dry-run`, and a dry run
  of an action policy would deny fails with that denial.
- **Decided, then audited.** Carrying an action out is a policy decision taken before anything is sent
  to the cluster: a denied action sends no request at all. The decision and the outcome are audited with
  the cluster, the object and, for a scale, the replica count.
- **From automations** the actor is `automation/<id>`, and the same rules apply: the safe actions
  run, and a drain is denied unless that automation is granted dangerous actions or an operator
  approves it (see [automations.md](automations.md#kubernetes-actions)). The automation runtime
  decides on and audits each action itself, once; the Kubernetes integration carries out an action
  only inside a policy decision that allowed that very action.
- **Drain** works like `kubectl drain`: it cordons the node, then evicts every pod on it through the
  Eviction API, so **PodDisruptionBudgets are honoured**. An eviction a budget refuses (HTTP 429) is
  retried every 5 seconds. DaemonSet pods and static (mirror) pods are skipped, as their controllers
  would put them straight back. The drain waits until the evicted pods are gone, up to a timeout (2
  minutes by default, at most 10); when it runs out, it stops and names the pods still there and why,
  and the node stays cordoned. Pods without a controller are evicted too, after a warning in the dry
  run.
