---
title: Runbook recipes
description: Ready-to-copy runbooks to add or upgrade a Talos node, add a k3s node or a Docker host.
---

Recipes are [runbooks](runbooks.md) for the jobs you do rarely enough to forget how: "how did I add a
node last time?". Copy one into the hub's runbooks directory, edit its `vars`, and run
`hearth runbook plan <id>` to see every step, with the vars filled in, and the policy decision it would
get before you start.

```sh
cp docs/recipes/runbooks/add-k3s-node.yaml <data-dir>/runbooks/
hearth runbook plan add-k3s-node
```

All four are built from the step types that exist today, so they have the same limits as any runbook:

- **Edit the vars at the top.** Devices, addresses, node and cluster names are
  [vars](runbooks.md#vars), named once and filled in where the steps use them. A prompt answer can never
  set one. The addresses in the recipes are from the documentation range (`192.0.2.0/24`), which
  reaches nothing real until you change them.
- **Dangerous steps are held, not bypassed.** The steps that change a machine are `exec` actions, and
  the Node deletion is a `kube_node_delete`: both are dangerous. They are denied, or held for approval,
  until you grant the runbook (`hearth hub --allow-dangerous-automation runbook/<id>`) or approve each
  one (see [guardrails](guardrails.md)). Each device's agent must also allow the program with
  `--allow-exec`.
- **A person approves every change.** A confirm prompt comes before each step that changes a machine,
  and says what that step does. Steps that only read, such as `talosctl health`, need none.
- **No fixed waits.** A recipe waits for a machine with a check that polls (`within`, `every`), never
  with a `wait` step that may end too soon.
- **No secret is in a recipe.** Keys and tokens stay in files on the device that needs them, which the
  recipe only names, so they are in no prompt, plan, run log or audit entry.
- **Nothing is piped from the internet into a shell.** A downloaded installer or signing key is
  checked against a sha256 or fingerprint pinned in the vars before it is used.
- **Rollback undoes what a step changed**, last step first. The k3s recipe uninstalls k3s, then
  deletes the Node object it left in the cluster. That needs the cluster [adopted](kubernetes.md) on the
  hub, as does the `kube_node` check that waits for the node to be Ready. The Talos recipe rolls back
  nothing on its own: it shows how to remove the node by hand.

These recipes were checked by the runbook parser and a plan (dry run) in the test suite, and the steps
of the Talos, k3s and Docker recipes in order against a stand-in agent, Kubernetes and Talos API. They
have not been run against a real Talos, k3s or Docker host. Try one on a spare machine first, and tell
us what needs fixing.

## Add a Talos node

Joins a Talos node, worker or control plane, booted in maintenance mode. Before it changes anything it
checks through the Talos API that the hub reads the cluster and that a control-plane node is healthy,
runs `talosctl health`, and checks that the new node's API answers. A prompt names the node's role and
the etcd quorum risk of adding a control plane (two members need both up), and the go-ahead prompt
explains the risk of `talosctl apply-config --insecure`: in maintenance mode talosctl cannot verify the
node, so the machine config, with the cluster's secrets, goes to whatever answers at that address
(trust on first use). After the config is applied, a
[`talos_node` check](runbooks.md#a-talos-node-runs-a-version) waits for the node to answer with every
service healthy, a `kube_node` check waits for it to be Ready, and `talosctl health` checks the cluster
again.

Rollback does not reset the node: a reset of a node that may already be an etcd member is a decision
for a person. The go-ahead prompt and the file's comment say how to remove the node by hand, and a
roll back writes the same to the hub's log.

The `talos_node` check of the new node needs its address among the nodes the hub reads: add it to
`--talos-nodes` (or the talosconfig context's nodes) before the run (see [Talos](talos.md)).

The file: [`docs/recipes/runbooks/add-talos-node.yaml`](recipes/runbooks/add-talos-node.yaml).

```yaml
# Add a Talos node, worker or control plane, to an existing cluster.
#
# Not yet run on real hardware: try it on a spare cluster first.
#
# Prerequisites:
#   - A Hearth agent runs on the machine that has talosctl and your Talos
#     configs (a workstation or the hub host). Its flags let it run talosctl:
#       hearth agent run --allow-exec /usr/local/bin/talosctl
#   - On that machine: the new node's machine config (worker.yaml or
#     controlplane.yaml from talosctl gen config, with your patches applied),
#     and /etc/talos/talosconfig (client config with the cluster endpoints).
#     Hearth never sees their content, so no secret is in this file.
#   - The new node is booted from the Talos image and waits in maintenance mode.
#   - The hub reads the Talos nodes (hearth hub --talosconfig, see docs/talos.md),
#     and the new node's address is among the nodes it reads: add it to
#     --talos-nodes (or to the talosconfig context's nodes) and restart the hub
#     before the run. Otherwise the check that waits for the new node never passes.
#   - The cluster is adopted on the hub's Platforms page, so the hub can check
#     that the node is Ready.
#   - Edit the vars below: the device with talosctl, the new node's address,
#     the name it registers with (its hostname, as the machine config sets it),
#     its role, the machine config's path, a control-plane address to run the
#     health checks from, and the cluster's name on the Platforms page.
#
# apply-config --insecure trusts on first use: talosctl cannot verify the node
# it talks to, so the machine config, with the cluster's secrets in it, goes to
# whatever answers at node-ip. Run this on a network you trust, and check that
# the address is the one the new node's console shows.
#
# Rollback is guidance only: nothing is reset or deleted automatically. A node
# that did not install can be powered off and booted again. A node that joined
# is removed by hand:
#   - worker: kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data,
#     then talosctl -n <node-ip> reset, then kubectl delete node <node-name>.
#   - control plane: talosctl -n <node-ip> reset --graceful (it leaves etcd first),
#     then kubectl delete node <node-name>. If the node cannot leave on its own,
#     run talosctl -n <healthy control plane> etcd remove-member <member> first.
#
# The talosctl steps are exec actions, which are dangerous: they are held or
# denied until the hub grants them, for example:
#   hearth hub --allow-dangerous-automation runbook/add-talos-node
id: add-talos-node
description: >-
  Join a Talos node after checks of the cluster's health, apply its machine config in maintenance
  mode, wait until it is healthy through the Talos API and Ready in Kubernetes. No automatic rollback.
vars:
  talosctl-device: workstation
  node-ip: 192.0.2.50
  node-name: talos-worker-1
  role: worker
  machine-config: /etc/talos/worker.yaml
  health-node: 192.0.2.10
  cluster: homelab
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the new node booted from the Talos image, are ${{ vars.machine-config }} and the talosconfig in
      place on ${{ vars.talosctl-device }}, is ${{ vars.node-ip }} among the nodes the hub reads, and
      are the vars in this runbook edited?
    timeout: 30m

  - id: hub-talos-access
    type: check
    description: The hub reads the cluster through the Talos API, and every service on a control-plane node is healthy.
    check:
      type: talos_node
      node: ${{ vars.health-node }}
      healthy: true
    within: 2m
    every: 10s

  - id: health-before
    type: action
    description: The cluster is healthy before the node joins (etcd, every node Ready, control plane up). Changes nothing.
    action:
      type: exec
      device: ${{ vars.talosctl-device }}
      command:
        - /usr/local/bin/talosctl
        - --talosconfig
        - /etc/talos/talosconfig
        - --nodes
        - ${{ vars.health-node }}
        - health
        - --wait-timeout
        - 5m
      timeout: 6m

  - id: maintenance-api
    type: check
    description: The new node's Talos API answers in maintenance mode.
    check:
      type: tcp
      address: "${{ vars.node-ip }}:50000"
    within: 10m
    every: 10s

  - id: quorum
    type: prompt
    prompt: confirm
    message: >-
      The new node's role is ${{ vars.role }}. For a worker, answer yes. For a control-plane node: it
      becomes an etcd member, and etcd needs a majority of its members up. Going from one to two
      members means both must be up, so a second control plane that fails to join stops the
      Kubernetes API; go on to three soon after. Answer yes only if every etcd member is healthy now
      and you accept that.
    timeout: 30m

  - id: approve
    type: prompt
    prompt: confirm
    message: >-
      Send ${{ vars.machine-config }} to ${{ vars.node-ip }} now, with talosctl apply-config --insecure?
      The node is in maintenance mode, so talosctl cannot verify who answers at that address: the config,
      with the cluster's secrets in it, goes to whatever does (trust on first use). Answer yes only on a
      network you trust, with the address checked on the node's console. The node installs Talos and
      reboots. Nothing is undone automatically. To remove the node later: for a worker, kubectl drain
      it, then talosctl -n ${{ vars.node-ip }} reset; for a control plane, talosctl -n ${{ vars.node-ip }}
      reset --graceful; then kubectl delete node ${{ vars.node-name }}.
    timeout: 1h

  - id: apply-config
    type: action
    description: >-
      Send the machine config to the node in maintenance mode; it installs Talos, reboots and joins.
      Not undone automatically: see the rollback note.
    action:
      type: exec
      device: ${{ vars.talosctl-device }}
      command:
        - /usr/local/bin/talosctl
        - apply-config
        - --insecure
        - --nodes
        - ${{ vars.node-ip }}
        - --file
        - ${{ vars.machine-config }}
      timeout: 5m
    rollback:
      type: log
      message: >-
        Nothing was undone on ${{ vars.node-name }} (${{ vars.node-ip }}). If it never installed, power it off.
        If it joined: for a worker, kubectl drain it, then talosctl -n ${{ vars.node-ip }} reset; for a
        control plane, talosctl -n ${{ vars.node-ip }} reset --graceful. Then kubectl delete node ${{ vars.node-name }}.

  - id: node-healthy
    type: check
    description: The new node answers through the Talos API with its own certificates, and every service on it is healthy.
    check:
      type: talos_node
      node: ${{ vars.node-ip }}
      healthy: true
    within: 20m
    every: 15s

  - id: node-ready
    type: check
    description: The new node registered and is Ready.
    check:
      type: kube_node
      cluster: ${{ vars.cluster }}
      node: ${{ vars.node-name }}
    within: 15m
    every: 15s

  - id: health-after
    type: action
    description: The cluster is healthy with the new node (for a control plane, etcd with the new member). Changes nothing.
    action:
      type: exec
      device: ${{ vars.talosctl-device }}
      command:
        - /usr/local/bin/talosctl
        - --talosconfig
        - /etc/talos/talosconfig
        - --nodes
        - ${{ vars.health-node }}
        - health
        - --wait-timeout
        - 5m
      timeout: 6m

  - id: done
    type: action
    action:
      type: log
      message: Talos ${{ vars.role }} node ${{ vars.node-name }} joined, is healthy and Ready.
```

## Upgrade a Talos node

Upgrades one Talos node to a new installer image. Before it changes anything it runs `talosctl health`
(etcd healthy, every node Ready, control plane up), checks through the Talos API that every service on
the node is healthy and through Kubernetes that the node is Ready, and asks you to confirm that taking
the node down keeps etcd's quorum: on the only control-plane node, the Kubernetes API and etcd are down
while it reboots, so answer no there unless you accept that outage. A last prompt asks for the
go-ahead, then `talosctl upgrade --preserve --wait` upgrades the node and waits until it has rebooted
into the new image. An exec action runs for 10 minutes at most, so an upgrade that takes longer ends
that step as `unknown`: look at the node, then retry or pass over. A
[`talos_node` check](runbooks.md#a-talos-node-runs-a-version) then waits for the node to answer
through the Talos API at the new version with every service healthy, the run waits for its Ready
condition, and `talosctl health` checks the cluster again. Rollback runs `talosctl rollback`, which
boots the node back into its previous Talos version. Never roll back a node that did not reboot into
the new version: the rollback would boot the version before the current one. The version check's error
says which version the node runs.

The `talos_node` checks need the hub to read the Talos nodes (`hearth hub --talosconfig`, see
[Talos](talos.md)), with the node's address among the nodes it reads.

**Not run on real hardware yet.** Try it on a spare cluster first, one node at a time.

The file: [`docs/recipes/runbooks/upgrade-talos-node.yaml`](recipes/runbooks/upgrade-talos-node.yaml).

```yaml
# Upgrade one Talos node to a new Talos version.
#
# Not yet run on real hardware: try it on a spare cluster first.
#
# Prerequisites:
#   - A Hearth agent runs on the machine that has talosctl and your talosconfig
#     (a workstation or the hub host). Its flags let it run talosctl:
#       hearth agent run --allow-exec /usr/local/bin/talosctl
#   - /etc/talos/talosconfig (client config with the cluster endpoints) exists
#     on that machine. Hearth never sees its content.
#   - The hub reads the Talos nodes (hearth hub --talosconfig, see docs/talos.md):
#     the talos_node checks read the node's version and services through it. The
#     node-ip var must be one of the nodes the hub reads: a node of the
#     talosconfig context, or of --talos-nodes. An os:reader talosconfig is enough.
#   - The cluster is adopted on the hub's Platforms page, so the hub can check
#     that the node is Ready.
#   - Edit the vars below: the device with talosctl, the node's name and address,
#     a control-plane address to run the health checks from, the installer image
#     and the version it installs, and the cluster's name on the Platforms page.
#   - Upgrade one node at a time: workers first, then control planes, one by one.
#   - The upgrade step waits for talosctl to finish, at most 9 minutes (exec
#     actions run for 10 at most). A slower upgrade ends the step as unknown:
#     look at the node, then retry or pass over. Never roll back a node that
#     did not reboot into the new version.
#   - After the upgrade, the run checks through the Talos API that the node runs
#     the new version with every service healthy. If that check fails, roll back
#     only if the node runs the new version and misbehaves: a node still at the
#     old version never rebooted, and talosctl rollback would boot the version
#     before that one.
#   - talosctl health stays an exec step: it checks the whole cluster (etcd
#     members, every node, the control plane), which a talos_node check of one
#     node does not.
#
# The talosctl steps are exec actions, which are dangerous: they are held or
# denied until the hub grants them, for example:
#   hearth hub --allow-dangerous-automation runbook/upgrade-talos-node
id: upgrade-talos-node
description: >-
  Upgrade one Talos node after health and quorum checks, check through the Talos API that it runs the
  new version with healthy services and wait for it to be Ready, undo with a talosctl rollback.
vars:
  talosctl-device: workstation
  node-name: talos-worker-1
  node-ip: 192.0.2.50
  health-node: 192.0.2.10
  installer-image: ghcr.io/siderolabs/installer:v1.12.8
  version: v1.12.8
  cluster: homelab
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the talosconfig in place on ${{ vars.talosctl-device }}, and are the vars in this
      runbook edited for ${{ vars.node-name }} (${{ vars.node-ip }}) and ${{ vars.installer-image }}?
    timeout: 30m

  - id: quorum
    type: prompt
    prompt: confirm
    message: >-
      Is ${{ vars.node-name }} a worker, or one of at least three control-plane nodes with every
      etcd member healthy? Answer no if it is your only control-plane node: the Kubernetes API and
      etcd are down while it reboots. Answer yes for that node only if you accept that outage.
    timeout: 30m

  - id: health-before
    type: action
    description: The cluster is healthy before the upgrade (etcd, every node Ready, control plane up).
    action:
      type: exec
      device: ${{ vars.talosctl-device }}
      command:
        - /usr/local/bin/talosctl
        - --talosconfig
        - /etc/talos/talosconfig
        - --nodes
        - ${{ vars.health-node }}
        - health
        - --wait-timeout
        - 5m
      timeout: 6m

  - id: node-healthy-before
    type: check
    description: The node answers through the Talos API and every service on it is healthy.
    check:
      type: talos_node
      node: ${{ vars.node-ip }}
      healthy: true
    within: 2m
    every: 10s

  - id: node-ready-before
    type: check
    description: The node is Ready before it is upgraded.
    check:
      type: kube_node
      cluster: ${{ vars.cluster }}
      node: ${{ vars.node-name }}
    within: 2m
    every: 10s

  - id: approve
    type: prompt
    prompt: confirm
    message: >-
      Upgrade ${{ vars.node-name }} at ${{ vars.node-ip }} to ${{ vars.installer-image }} now? The
      node reboots, and its pods move or wait until it is back. If the run stops after the upgrade,
      roll back only if the node runs ${{ vars.version }} and misbehaves: if it never rebooted and still
      runs the old version, do NOT roll back, as talosctl rollback would boot the version before that
      one.
    timeout: 1h

  - id: upgrade
    type: action
    description: >-
      Upgrade the node and wait until it has rebooted into the new image; talosctl fails the
      step if the upgrade fails.
    action:
      type: exec
      device: ${{ vars.talosctl-device }}
      command:
        - /usr/local/bin/talosctl
        - --talosconfig
        - /etc/talos/talosconfig
        - --nodes
        - ${{ vars.node-ip }}
        - upgrade
        - --image
        - ${{ vars.installer-image }}
        - --preserve
        - --wait
        - --timeout
        - 9m
      timeout: 10m
    rollback:
      type: exec
      device: ${{ vars.talosctl-device }}
      command:
        - /usr/local/bin/talosctl
        - --talosconfig
        - /etc/talos/talosconfig
        - --nodes
        - ${{ vars.node-ip }}
        - rollback
      timeout: 5m

  - id: version-after
    type: check
    description: >-
      The node is back, runs the new version and every service on it is healthy. If this fails, roll
      back only if the node runs the new version and misbehaves: if it never rebooted and still runs
      the old version, do NOT roll back, as talosctl rollback would boot the version before that one.
    check:
      type: talos_node
      node: ${{ vars.node-ip }}
      version: ${{ vars.version }}
      healthy: true
    within: 20m
    every: 15s

  - id: node-ready-after
    type: check
    description: The node is Ready again.
    check:
      type: kube_node
      cluster: ${{ vars.cluster }}
      node: ${{ vars.node-name }}
    within: 20m
    every: 15s

  - id: health-after
    type: action
    description: The cluster is healthy after the upgrade.
    action:
      type: exec
      device: ${{ vars.talosctl-device }}
      command:
        - /usr/local/bin/talosctl
        - --talosconfig
        - /etc/talos/talosconfig
        - --nodes
        - ${{ vars.health-node }}
        - health
        - --wait-timeout
        - 5m
      timeout: 6m

  - id: done
    type: action
    action:
      type: log
      message: Talos node ${{ vars.node-name }} runs ${{ vars.version }} and the cluster is healthy.
```

## Add a k3s node

Joins a machine that runs a Hearth agent to a k3s cluster as an agent node, at a pinned k3s version.
It downloads `install.sh` at that version's tag, checks it against the sha256 pinned in the vars, asks
for the go-ahead, checks it again and runs it; `install.sh` checks the k3s binary against the release's
checksums. The join token stays in a root-only file on the machine, which k3s reads: Hearth never sees
it. A `kube_node` check waits for the node to be Ready. Rollback runs the k3s uninstaller and deletes
the Node object.

The agent's systemd unit keeps `/usr` and `/etc` read-only, so the install needs a drop-in that lifts
that for the run; the file's comment shows it.

The file: [`docs/recipes/runbooks/add-k3s-node.yaml`](recipes/runbooks/add-k3s-node.yaml).

```yaml
# Add a k3s agent (worker) node to an existing k3s cluster.
#
# Not yet run on real hardware: try it on a spare machine first.
#
# Prerequisites:
#   - The new machine runs a Hearth agent that is enrolled with the hub, runs
#     as root and is allowed to run the programs below:
#       hearth agent run --allow-exec /bin/sh \
#         --allow-exec /usr/local/bin/k3s-agent-uninstall.sh --allow-exec /bin/rm
#     Allowing sh is a wide grant: the agent can then run anything. Remove it
#     from the agent again after the run.
#   - The agent's systemd unit keeps /usr and /etc read-only (ProtectSystem=full).
#     For the run, let it write there with a drop-in, and restart the agent:
#       sudo systemctl edit hearth-agent    # add: [Service] ProtectSystem=no
#       sudo systemctl restart hearth-agent
#     After the run, remove the drop-in (sudo systemctl revert hearth-agent)
#     and restart the agent again. Keep PrivateTmp=yes: the installer is
#     downloaded to the agent's own /tmp.
#   - The cluster's join token is in a root-only file on the new machine,
#     /etc/hearth/k3s-token (mode 0600). Put it there yourself: this runbook only
#     names the file. k3s reads it there, and Hearth never sees it, so it is in
#     no prompt, step or audit entry.
#   - curl and sha256sum are on the machine, and it can reach GitHub.
#   - The server answers on port 6443 and the machine can reach it.
#   - The cluster is adopted on the hub's Platforms page, so the hub can check
#     the node and delete its Node object on a rollback.
#   - Edit the vars below: the new device, the k3s server's address, the name
#     the node registers with (its hostname, by default), the cluster's name on
#     the Platforms page, the k3s version (use the server's) and the sha256 of
#     install.sh at that version. The two go together: when you change the
#     version, download install.sh from the same tag and put its sha256 here:
#       curl -sfL https://raw.githubusercontent.com/k3s-io/k3s/<version>/install.sh | sha256sum
#
# Nothing is piped from curl into a shell: install.sh is downloaded at the
# pinned tag, checked against the pinned sha256, and checked again right
# before it runs. install.sh itself installs the pinned k3s version and checks
# the binary against the release's sha256sum file.
#
# Install, uninstall and the Node deletion are dangerous: they are held or
# denied until the hub grants them, for example:
#   hearth hub --allow-dangerous-automation runbook/add-k3s-node
id: add-k3s-node
description: >-
  Join a machine to a k3s cluster as an agent with a pinned, checksum-verified installer, check it is
  Ready, undo with the k3s uninstaller.
vars:
  device: k3s-new
  server-ip: 192.0.2.10
  node-name: k3s-new
  cluster: homelab
  k3s-version: v1.37.2+k3s1
  installer-sha256: ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the agent on ${{ vars.device }} enrolled, allowed to run sh, and able to write /usr and /etc,
      is the join token in /etc/hearth/k3s-token, and are the vars in this runbook edited?
    timeout: 30m

  - id: server-up
    type: check
    description: The k3s server's API answers.
    check:
      type: tcp
      address: "${{ vars.server-ip }}:6443"
    within: 2m
    every: 10s

  - id: approve-download
    type: prompt
    prompt: confirm
    message: >-
      Download install.sh of k3s ${{ vars.k3s-version }} from GitHub to ${{ vars.device }}, and check its
      sha256 is ${{ vars.installer-sha256 }}? Nothing runs yet.
    timeout: 1h

  - id: fetch-installer
    type: action
    description: >-
      Download install.sh at the pinned tag to the agent's private /tmp and check its sha256; a file
      that does not match is deleted and fails the step.
    action:
      type: exec
      device: ${{ vars.device }}
      command:
        - /bin/sh
        - -c
        - |-
          set -eu
          curl -sfL -o /tmp/k3s-install.sh "https://raw.githubusercontent.com/k3s-io/k3s/$1/install.sh"
          echo "$2  /tmp/k3s-install.sh" | sha256sum -c - || { rm -f /tmp/k3s-install.sh; exit 1; }
        - sh
        - ${{ vars.k3s-version }}
        - ${{ vars.installer-sha256 }}
      timeout: 2m
    rollback:
      type: exec
      device: ${{ vars.device }}
      command: [/bin/rm, -f, /tmp/k3s-install.sh]

  - id: forget-node
    type: action
    description: >-
      Nothing to do on the way forward. On a rollback, this runs after k3s is
      uninstalled and deletes the Node object it left in the cluster.
    action:
      type: log
      message: On a rollback, the Node ${{ vars.node-name }} is deleted after the uninstall.
    rollback:
      type: kube_node_delete
      cluster: ${{ vars.cluster }}
      node: ${{ vars.node-name }}

  - id: approve-install
    type: prompt
    prompt: confirm
    message: >-
      The installer matched its sha256. Install k3s ${{ vars.k3s-version }} as an agent on
      ${{ vars.device }} now, joining https://${{ vars.server-ip }}:6443 with the token in
      /etc/hearth/k3s-token? It starts the k3s-agent service; a rollback runs k3s-agent-uninstall.sh
      and deletes the Node ${{ vars.node-name }}.
    timeout: 1h

  - id: install
    type: action
    description: >-
      Check the installer's sha256 again, then install k3s as an agent and join the server; k3s reads
      the token from its file.
    action:
      type: exec
      device: ${{ vars.device }}
      command:
        - /bin/sh
        - -c
        - |-
          set -eu
          umask 022
          test -s "$4" || { echo "no join token in $4" >&2; exit 1; }
          echo "$2  /tmp/k3s-install.sh" | sha256sum -c -
          INSTALL_K3S_VERSION="$1" sh /tmp/k3s-install.sh agent --server "$3" --token-file "$4"
        - sh
        - ${{ vars.k3s-version }}
        - ${{ vars.installer-sha256 }}
        - "https://${{ vars.server-ip }}:6443"
        - /etc/hearth/k3s-token
      timeout: 10m
    rollback:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/local/bin/k3s-agent-uninstall.sh]
      timeout: 5m

  - id: node-ready
    type: check
    description: The node registered and is Ready.
    check:
      type: kube_node
      cluster: ${{ vars.cluster }}
      node: ${{ vars.node-name }}
    within: 10m
    every: 10s

  - id: done
    type: action
    action:
      type: log
      message: k3s ${{ vars.k3s-version }} node ${{ vars.node-name }} joined and is Ready.
```

## Add a Docker host

Installs Docker Engine on a Debian, Ubuntu or Raspberry Pi OS machine that runs a Hearth agent. It
adds Docker's apt repository, trusting its signing key only if the key's fingerprint matches the one
pinned in the vars, installs Docker Engine, adds a user to the `docker` group, and verifies with
`docker version` and a `hello-world` run, with a prompt before each change. Rollback removes the image,
the group membership, the packages and the repository. For Podman, which is in Debian's own
repositories, no recipe is needed: `apt-get install podman`.

As for k3s, the agent needs a systemd drop-in for the run, shown in the file's comment. Afterwards the
agent can be allowed to restart containers (`--allow-restart docker:NAME`). The Docker integration
(#64) adds `--allow-docker` for containers once it ships.

The file: [`docs/recipes/runbooks/add-docker-host.yaml`](recipes/runbooks/add-docker-host.yaml).

```yaml
# Install Docker Engine on a Debian, Ubuntu or Raspberry Pi OS machine.
#
# Not yet run on real hardware: try it on a spare machine first.
#
# Prerequisites:
#   - The machine (any hardware) has internet access, ca-certificates, curl and
#     gpg (apt-get install ca-certificates curl gnupg), and runs a Hearth agent
#     that is enrolled with the hub, runs as root and is allowed to run:
#       hearth agent run --allow-exec /bin/sh --allow-exec /bin/rm \
#         --allow-exec /usr/bin/apt-get --allow-exec /usr/bin/docker \
#         --allow-exec /usr/sbin/usermod --allow-exec /usr/bin/gpasswd
#     Allowing sh is a wide grant: the agent can then run anything. Remove it
#     from the agent again after the run.
#   - The agent's systemd unit keeps /usr and /etc read-only (ProtectSystem=full)
#     and forbids setuid files (RestrictSUIDSGID=yes), which a package may
#     install. For the run, lift both with a drop-in, and restart the agent:
#       sudo systemctl edit hearth-agent
#       # add: [Service] ProtectSystem=no RestrictSUIDSGID=no (one per line)
#       sudo systemctl restart hearth-agent
#     After the run, remove the drop-in (sudo systemctl revert hearth-agent)
#     and restart the agent again.
#   - The machine answers on SSH (port 22), which the first check uses to see it
#     is on the network. Change the port in that check if it runs no SSH.
#   - Edit the vars below: the device, its address, Docker's repository for the
#     distribution (debian, ubuntu, or raspbian for 32-bit Raspberry Pi OS;
#     64-bit Raspberry Pi OS is debian) and the user to add to the docker group.
#   - key-fingerprint is the fingerprint of Docker's apt signing key, as Docker
#     publishes it in its install guide. The run refuses a key that differs.
#
# For Podman instead: it is in Debian's and Ubuntu's own repositories, so no
# repository or key is needed (apt-get install podman); this runbook does Docker.
#
# Afterwards, let the agent restart containers with --allow-restart
# docker:<container>. The Docker integration (issue #64) adds --allow-docker
# for containers once it ships.
#
# The exec actions are dangerous: they are held or denied until the hub grants
# them, for example:
#   hearth hub --allow-dangerous-automation runbook/add-docker-host
id: add-docker-host
description: >-
  Add Docker's apt repository with a pinned key fingerprint, install Docker Engine, add a user to the
  docker group, verify with docker version and hello-world, undo with a purge.
vars:
  device: docker-new
  address: 192.0.2.70
  distro: debian
  key-fingerprint: 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
  user: pi
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the agent on ${{ vars.device }} enrolled, allowed to run the programs listed in this runbook,
      and able to write /usr and /etc, and are the vars edited?
    timeout: 30m

  - id: host-up
    type: check
    description: The machine answers on SSH, so it is on the network.
    check:
      type: tcp
      address: "${{ vars.address }}:22"
    within: 2m
    every: 10s

  - id: approve-repo
    type: prompt
    prompt: confirm
    message: >-
      Add Docker's apt repository for ${{ vars.distro }} to ${{ vars.device }}? Its signing key is
      downloaded and trusted only if its fingerprint is ${{ vars.key-fingerprint }}.
    timeout: 1h

  - id: add-repo
    type: action
    description: >-
      Download Docker's signing key, check that it is one key with the pinned fingerprint, install it
      in /etc/apt/keyrings and add the repository for this release.
    action:
      type: exec
      device: ${{ vars.device }}
      command:
        - /bin/sh
        - -c
        - |-
          set -eu
          umask 022
          tmp=$(mktemp -d)
          trap 'rm -rf "$tmp"' EXIT
          curl -fsSL -o "$tmp/docker.asc" "https://download.docker.com/linux/$1/gpg"
          keys=$(GNUPGHOME="$tmp" gpg --batch --show-keys --with-colons "$tmp/docker.asc")
          [ "$(printf '%s\n' "$keys" | grep -c '^pub:')" = 1 ] || { echo "want exactly one key" >&2; exit 1; }
          got=$(printf '%s\n' "$keys" | grep -m1 '^fpr:' | cut -d: -f10)
          [ "$got" = "$2" ] || { echo "key fingerprint is $got, want $2" >&2; exit 1; }
          install -d -m 0755 /etc/apt/keyrings
          install -m 0644 "$tmp/docker.asc" /etc/apt/keyrings/docker.asc
          . /etc/os-release
          echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$1 $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
        - sh
        - ${{ vars.distro }}
        - ${{ vars.key-fingerprint }}
      timeout: 2m
    rollback:
      type: exec
      device: ${{ vars.device }}
      command: [/bin/rm, -f, /etc/apt/sources.list.d/docker.list, /etc/apt/keyrings/docker.asc]

  - id: approve-install
    type: prompt
    prompt: confirm
    message: >-
      Install Docker Engine (docker-ce, its CLI, containerd and the buildx and compose plugins) on
      ${{ vars.device }} from that repository? Docker starts now and at every boot.
    timeout: 1h

  - id: install
    type: action
    description: Install Docker Engine from Docker's apt repository; the package starts and enables it.
    action:
      type: exec
      device: ${{ vars.device }}
      command:
        - /bin/sh
        - -c
        - |-
          set -eu
          umask 022
          export DEBIAN_FRONTEND=noninteractive
          apt-get update
          apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      timeout: 10m
    rollback:
      type: exec
      device: ${{ vars.device }}
      command:
        - /usr/bin/apt-get
        - purge
        - -y
        - docker-ce
        - docker-ce-cli
        - containerd.io
        - docker-buildx-plugin
        - docker-compose-plugin
      timeout: 5m

  - id: verify
    type: action
    description: Ask the daemon for its version, which fails if it is not running. Changes nothing.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/docker, version, --format, "{{.Server.Version}}"]
      timeout: 1m

  - id: approve-group
    type: prompt
    prompt: confirm
    message: >-
      Add ${{ vars.user }} to the docker group on ${{ vars.device }}? Members of that group control the
      daemon, which is the same as root on that machine. A rollback removes ${{ vars.user }} from the
      group again, even if it was a member before.
    timeout: 1h

  - id: group
    type: action
    description: Let the user run docker without sudo, from their next login.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/sbin/usermod, -aG, docker, "${{ vars.user }}"]
    rollback:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/gpasswd, -d, "${{ vars.user }}", docker]

  - id: approve-hello
    type: prompt
    prompt: confirm
    message: >-
      Run the hello-world container on ${{ vars.device }} to check that containers start? It pulls the
      hello-world image from Docker Hub.
    timeout: 1h

  - id: hello-world
    type: action
    description: Pull and run hello-world, which exits 0 when a container ran.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/docker, run, --rm, hello-world]
      timeout: 5m
    rollback:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/docker, image, rm, hello-world]

  - id: done
    type: action
    action:
      type: log
      message: >-
        Docker host ${{ vars.device }} is ready. Remove the agent's systemd drop-in and its sh grant, and
        add --allow-restart docker:<container> for the containers Hearth should restart.
```

## What the recipes cannot do yet

- **Talos changes go through `talosctl`.** The [Talos integration](talos.md) only reads, so the Talos
  recipes drive `talosctl` on a device with an agent, which needs `--allow-exec` on that device and a
  grant for dangerous actions. The k3s and Docker recipes need a wide `sh` grant for the same reason:
  an `exec` action runs one program with its arguments, with no environment, pipe or stdin, so a
  checksum check runs as `sh -c` with the pinned values passed as arguments, never pasted into the
  script.
- **Installs need the agent's sandbox lifted.** The agent's systemd unit keeps `/usr` and `/etc`
  read-only, so the k3s and Docker recipes ask for a drop-in for the run.
- **No step depends on an answer or a var.** Every step runs on every run. The Talos recipe asks the
  etcd quorum question for a worker too, and a worker answers yes.
- **A secret cannot reach a command.** A secret prompt's answer can only fill a webhook body or header,
  so the k3s join token is read from a file on the machine.
