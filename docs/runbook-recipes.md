---
title: Runbook recipes
description: Ready-to-copy runbooks to add a Talos node, a k3s node or a Docker host.
---

Recipes are [runbooks](runbooks.md) for the jobs you do rarely enough to forget how: "how did I add a
node last time?". Copy one into the hub's runbooks directory, edit its `vars`, and run
`hearth runbook plan <id>` to see every step, with the vars filled in, and the policy decision it would
get before you start.

```sh
cp docs/recipes/runbooks/add-k3s-node.yaml <data-dir>/runbooks/
hearth runbook plan add-k3s-node
```

All three are built from the step types that exist today, so they have the same limits as any runbook:

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

These recipes were checked by the runbook parser and a plan (dry run) in the test suite. They have not
been run against a real Talos, k3s or Docker host. Try one on a spare machine first, and tell us what
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

- **No Talos integration.** Talos is driven through `talosctl` on a device with an agent, which needs
  `--allow-exec` on that device and a grant for dangerous actions. The k3s and Docker recipes need a
  wide `sh` grant for the same reason. Native, policy-classed Talos actions (apply-config, reset,
  health) are planned in [#63](https://github.com/gvart/hearth/issues/63); the Talos recipe will move
  to them when they land.
