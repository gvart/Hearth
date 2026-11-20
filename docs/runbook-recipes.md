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
- **No secret is in a recipe.** Keys and tokens stay in files on the device that needs them, which the
  recipe only names.
- **Rollback undoes what a step changed**, last step first. The Talos and k3s recipes reset or
  uninstall the node, then delete the Node object it left in the cluster. That needs the cluster
  [adopted](kubernetes.md) on the hub, as does the `kube_node` check that waits for the node to be Ready.

These recipes were checked by the runbook parser and a plan (dry run) in the test suite, and the Talos
upgrade's steps in order against a stand-in agent. They have not been run against a real Talos, k3s or
Docker host. Try one on a spare machine first, and tell us what
needs fixing.

## Add a Talos node

Joins a Talos worker node booted in maintenance mode: checks its API, applies the worker config with `talosctl` from a device that holds your configs, and waits for the node to be Ready in the cluster. Rollback resets the node and deletes its Node object.

The file: [`docs/recipes/runbooks/add-talos-node.yaml`](recipes/runbooks/add-talos-node.yaml).

```yaml
# Add a Talos worker node to an existing cluster.
#
# Prerequisites:
#   - A Hearth agent runs on the machine that has talosctl and your Talos
#     configs (a workstation or the hub host). Its flags let it run talosctl:
#       hearth agent run --allow-exec /usr/local/bin/talosctl
#   - /etc/talos/worker.yaml (the worker machine config) and
#     /etc/talos/talosconfig (client config with the cluster endpoints) exist on
#     that machine. Hearth never sees their content, so no secret is in this file.
#   - The new node is booted from the Talos image and waits in maintenance mode.
#   - The cluster is adopted on the hub's Kubernetes page, so the hub can check
#     the node and delete its Node object on a rollback.
#   - Edit the vars below: the device with talosctl, the new node's address and
#     the name it registers with (its hostname, as worker.yaml sets it), and the
#     cluster's name on the Kubernetes page.
#
# apply-config, the reset and the Node deletion are dangerous: they are held or
# denied until the hub grants them, for example:
#   hearth hub --allow-dangerous-automation runbook/add-talos-node
id: add-talos-node
description: Join a Talos worker node, check it is Ready, undo with a node reset and a Node deletion.
vars:
  talosctl-device: workstation
  node-ip: 192.0.2.50
  node-name: talos-worker-1
  cluster: homelab
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the new node booted from the Talos image, are worker.yaml and talosconfig
      in place on ${{ vars.talosctl-device }}, and are the vars in this runbook edited?
    timeout: 30m

  - id: maintenance-api
    type: check
    description: The node's Talos API answers in maintenance mode.
    check:
      type: tcp
      address: "${{ vars.node-ip }}:50000"
    within: 10m
    every: 10s

  - id: forget-node
    type: action
    description: >-
      Nothing to do on the way forward. On a rollback, this runs after the node is
      reset and deletes the Node object it left in the cluster.
    action:
      type: log
      message: On a rollback, the Node ${{ vars.node-name }} is deleted after the reset.
    rollback:
      type: kube_node_delete
      cluster: ${{ vars.cluster }}
      node: ${{ vars.node-name }}

  - id: apply-config
    type: action
    description: Send the worker machine config to the node; it installs and reboots.
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
        - /etc/talos/worker.yaml
      timeout: 5m
    rollback:
      type: exec
      device: ${{ vars.talosctl-device }}
      command:
        - /usr/local/bin/talosctl
        - --talosconfig
        - /etc/talos/talosconfig
        - reset
        - --nodes
        - ${{ vars.node-ip }}
        - --graceful=false
        - --reboot
      timeout: 5m

  - id: install-settle
    type: wait
    description: Give the node time to install Talos and reboot.
    duration: 2m

  - id: node-ready
    type: check
    description: The node registered and is Ready.
    check:
      type: kube_node
      cluster: ${{ vars.cluster }}
      node: ${{ vars.node-name }}
    within: 15m
    every: 15s

  - id: done
    type: action
    action:
      type: log
      message: Talos node ${{ vars.node-name }} joined and is Ready.
```

## Upgrade a Talos node

Upgrades one Talos node to a new installer image. Before it changes anything it runs `talosctl health`
(etcd healthy, every node Ready, control plane up), checks that the node is Ready, and asks you to
confirm that taking the node down keeps etcd's quorum: on the only control-plane node, the Kubernetes
API and etcd are down while it reboots, so answer no there unless you accept that outage. A last prompt
asks for the go-ahead, then `talosctl upgrade --preserve` starts the upgrade, and the run waits for the
node's Talos API and its Ready condition to come back. You confirm the new version on the
[From Talos](talos.md) table, and `talosctl health` checks the cluster again. Rollback runs
`talosctl rollback`, which boots the node back into its previous Talos version.

Runbooks have no step that reads the output of a command or a node's Talos version, so the version
check is a prompt: compare the version the Devices page shows with the one you upgraded to.

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
#   - The hub reads the Talos nodes (hearth hub --talosconfig, see docs/talos.md),
#     so the Devices page shows each node's Talos version.
#   - The cluster is adopted on the hub's Kubernetes page, so the hub can check
#     that the node is Ready.
#   - Edit the vars below: the device with talosctl, the node's name and address,
#     a control-plane address to run the health checks from, the installer image
#     and the version it installs, and the cluster's name on the Kubernetes page.
#   - Upgrade one node at a time: workers first, then control planes, one by one.
#
# The talosctl steps are exec actions, which are dangerous: they are held or
# denied until the hub grants them, for example:
#   hearth hub --allow-dangerous-automation runbook/upgrade-talos-node
id: upgrade-talos-node
description: Upgrade one Talos node after health and quorum checks, wait for it to be Ready, undo with a talosctl rollback.
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
      Upgrade ${{ vars.node-name }} to ${{ vars.installer-image }} now? The node reboots, and its pods
      move or wait until it is back.
    timeout: 1h

  - id: upgrade
    type: action
    description: Start the upgrade; the node installs the new image and reboots into it.
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
        - --wait=false
      timeout: 5m
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

  - id: reboot-settle
    type: wait
    description: Give the node time to install the image and reboot.
    duration: 3m

  - id: api-back
    type: check
    description: The node's Talos API answers again.
    check:
      type: tcp
      address: "${{ vars.node-ip }}:50000"
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

  - id: version-after
    type: prompt
    prompt: confirm
    message: >-
      Does the From Talos table on the Devices page show ${{ vars.node-name }} at ${{ vars.version }}
      and healthy? Answer no to stop here and roll back to the previous version.
    timeout: 1h

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

Joins a machine that runs a Hearth agent to a k3s cluster as an agent node, with the join token read from a root-only file on that machine, and waits for the node to be Ready. Rollback runs the k3s uninstaller and deletes the Node object.

The file: [`docs/recipes/runbooks/add-k3s-node.yaml`](recipes/runbooks/add-k3s-node.yaml).

```yaml
# Add a k3s agent (worker) node to an existing k3s cluster.
#
# Prerequisites:
#   - The new machine runs a Hearth agent that is enrolled with the hub and
#     allowed to run the programs below:
#       hearth agent run --allow-exec /usr/bin/curl --allow-exec /bin/sh \
#         --allow-exec /usr/local/bin/k3s-agent-uninstall.sh --allow-exec /bin/rm
#     Allowing sh is a wide grant: remove it from the agent again after the run.
#   - The cluster's join token is in a root-only file on the new machine,
#     /etc/hearth/k3s-token (mode 0600). Put it there yourself: this runbook
#     only names the file and never holds the token.
#   - The server answers on port 6443 and the machine can reach it.
#   - The cluster is adopted on the hub's Kubernetes page, so the hub can check
#     the node and delete its Node object on a rollback.
#   - Edit the vars below: the new device, the k3s server's address, the name
#     the node registers with (its hostname, by default) and the cluster's name
#     on the Kubernetes page.
#
# Install, uninstall and the Node deletion are dangerous: they are held or
# denied until the hub grants them, for example:
#   hearth hub --allow-dangerous-automation runbook/add-k3s-node
id: add-k3s-node
description: Join a machine to a k3s cluster as an agent, check it is Ready, undo with the k3s uninstaller.
vars:
  device: k3s-new
  server-ip: 192.0.2.10
  node-name: k3s-new
  cluster: homelab
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the agent on ${{ vars.device }} enrolled and allowed to run curl and sh, is the
      join token in /etc/hearth/k3s-token, and are the vars in this runbook edited?
    timeout: 30m

  - id: server-up
    type: check
    description: The k3s server's API answers.
    check:
      type: tcp
      address: "${{ vars.server-ip }}:6443"
    within: 2m
    every: 10s

  - id: fetch-installer
    type: action
    description: Download the k3s install script.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/curl, -sfL, -o, /tmp/k3s-install.sh, "https://get.k3s.io"]
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

  - id: install
    type: action
    description: Install k3s as an agent and join the server, reading the token from its file.
    action:
      type: exec
      device: ${{ vars.device }}
      command:
        - /bin/sh
        - /tmp/k3s-install.sh
        - agent
        - --server
        - "https://${{ vars.server-ip }}:6443"
        - --token-file
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
      message: k3s node ${{ vars.node-name }} joined and is Ready.
```

## Add a Docker host

Installs Docker Engine on a Debian-family machine that runs a Hearth agent, starts it, and verifies the daemon. Rollback disables and purges it. Afterwards the agent can be allowed to restart containers (`--allow-restart docker:NAME`).

The file: [`docs/recipes/runbooks/add-docker-host.yaml`](recipes/runbooks/add-docker-host.yaml).

```yaml
# Prepare a new machine as a Docker host that Hearth can restart containers on.
#
# Prerequisites:
#   - A Debian, Ubuntu or Raspberry Pi OS machine (any hardware) with internet
#     access, running a Hearth agent that is enrolled with the hub and runs as
#     root. Allow the programs this runbook runs:
#       hearth agent run --allow-exec /usr/bin/curl --allow-exec /bin/sh \
#         --allow-exec /usr/bin/systemctl --allow-exec /usr/bin/docker \
#         --allow-exec /usr/bin/apt-get --allow-exec /bin/rm
#     Allowing sh is a wide grant: remove it from the agent again after the run.
#   - Edit the vars below: the new device and its address.
#   - Afterwards, add --allow-restart docker:<container> to the agent for every
#     container Hearth should be able to restart.
#
# The exec actions are dangerous: they are held or denied until the hub grants
# them, for example:
#   hearth hub --allow-dangerous-automation runbook/add-docker-host
id: add-docker-host
description: Install Docker Engine on a machine, start it, verify it, undo with a purge.
vars:
  device: docker-new
  address: 192.0.2.70
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the agent on the new machine enrolled and allowed to run the programs listed
      in this runbook, and are the vars edited?
    timeout: 30m

  - id: host-up
    type: check
    description: The machine answers on SSH, so it is on the network.
    check:
      type: tcp
      address: "${{ vars.address }}:22"
    within: 2m
    every: 10s

  - id: fetch-installer
    type: action
    description: Download Docker's convenience install script.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/curl, -fsSL, -o, /tmp/get-docker.sh, "https://get.docker.com"]
      timeout: 2m
    rollback:
      type: exec
      device: ${{ vars.device }}
      command: [/bin/rm, -f, /tmp/get-docker.sh]

  - id: install
    type: action
    description: Install Docker Engine from Docker's apt repository.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/bin/sh, /tmp/get-docker.sh]
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

  - id: enable
    type: action
    description: Start Docker now and at every boot.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/systemctl, enable, --now, docker.service]
      timeout: 2m
    rollback:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/systemctl, disable, --now, docker.service, docker.socket]
      timeout: 2m

  - id: verify
    type: action
    description: Ask the daemon for its version, which fails if it is not running. Changes nothing.
    action:
      type: exec
      device: ${{ vars.device }}
      command: [/usr/bin/docker, version, --format, "{{.Server.Version}}"]
      timeout: 1m

  - id: allow-restarts
    type: prompt
    prompt: confirm
    message: >-
      Did you add --allow-restart docker:<container> to the agent for the containers
      Hearth should restart? Answer no to stop here; the host itself is ready.
    timeout: 30m

  - id: done
    type: action
    action:
      type: log
      message: Docker host is ready.
```

## What the recipes cannot do yet

- **Talos changes go through `talosctl`.** The [Talos integration](talos.md) only reads, so the Talos
  recipes drive `talosctl` on a device with an agent, which needs `--allow-exec` on that device and a
  grant for dangerous actions. The k3s and Docker recipes need a wide `sh` grant for the same reason.
