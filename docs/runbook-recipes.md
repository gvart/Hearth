---
title: Runbook recipes
description: Ready-to-copy runbooks to add a Talos node, a k3s node or a Docker host.
---

Recipes are [runbooks](runbooks.md) for the jobs you do rarely enough to forget how: "how did I add a
node last time?". Copy one into the hub's runbooks directory, edit the placeholders, and run
`hearth runbook plan <id>` to see every step and the policy decision it would get before you start.

```sh
cp docs/recipes/runbooks/add-k3s-node.yaml <data-dir>/runbooks/
hearth runbook plan add-k3s-node
```

All three are built from the step types that exist today, so they have the same limits as any runbook:

- **Edit the placeholders in every step.** A runbook has no variables yet: a prompt answer can never
  choose a device, an address or a command. The addresses in the recipes are from the documentation
  range (`192.0.2.0/24`), which reaches nothing real until you change them.
- **Dangerous steps are held, not bypassed.** The steps that change a machine are `exec` actions, which
  are dangerous. They are denied, or held for approval, until you grant the runbook
  (`hearth hub --allow-dangerous-automation runbook/<id>`) or approve each one (see
  [guardrails](guardrails.md)). Each device's agent must also allow the program with `--allow-exec`.
- **No secret is in a recipe.** Keys and tokens stay in files on the device that needs them, which the
  recipe only names.
- **Rollback undoes what a step changed**, last step first. It cannot remove the Node object from
  Kubernetes: Hearth has no action for that yet, so the recipes say so and leave it to you.

These recipes were checked by the runbook parser and a plan (dry run) in the test suite. They have not
been run against a real Talos, k3s or Docker host. Try one on a spare machine first, and tell us what
needs fixing.

## Add a Talos node

Joins a Talos worker node booted in maintenance mode: checks its API, applies the worker config with `talosctl` from a device that holds your configs, waits for the kubelet, and asks you to confirm the node is Ready. Rollback resets the node.

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
#   - Edit the placeholders below (192.0.2.50 is the new node, `workstation` is
#     the device with talosctl) in every step before you start the run.
#
# apply-config is an exec action, which is dangerous: it is held or denied until
# the hub grants it, for example:
#   hearth hub --allow-dangerous-automation runbook/add-talos-node
id: add-talos-node
description: Join a Talos worker node, check it comes up, undo with a node reset.
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the new node booted from the Talos image, are worker.yaml and talosconfig
      in place on the talosctl device, and are the placeholders in this runbook edited?
    timeout: 30m

  - id: maintenance-api
    type: check
    description: The node's Talos API answers in maintenance mode.
    check:
      type: tcp
      address: "192.0.2.50:50000"
    within: 10m
    every: 10s

  - id: apply-config
    type: action
    description: Send the worker machine config to the node; it installs and reboots.
    action:
      type: exec
      device: workstation
      command:
        - /usr/local/bin/talosctl
        - apply-config
        - --insecure
        - --nodes
        - 192.0.2.50
        - --file
        - /etc/talos/worker.yaml
      timeout: 5m
    rollback:
      type: exec
      device: workstation
      command:
        - /usr/local/bin/talosctl
        - --talosconfig
        - /etc/talos/talosconfig
        - reset
        - --nodes
        - 192.0.2.50
        - --graceful=false
        - --reboot
      timeout: 5m

  - id: install-settle
    type: wait
    description: Give the node time to install Talos and reboot.
    duration: 2m

  - id: kubelet
    type: check
    description: The kubelet of the joined node answers.
    check:
      type: tcp
      address: "192.0.2.50:10250"
    within: 15m
    every: 15s

  - id: node-ready
    type: prompt
    prompt: confirm
    message: >-
      Does the node show as Ready on the Kubernetes page? Answer no to stop the run,
      then roll back to reset the node. After a rollback, remove the stale Node
      object by hand: kubectl delete node <name>.
    timeout: 30m

  - id: done
    type: action
    action:
      type: log
      message: Talos node joined and confirmed Ready.
```

## Add a k3s node

Joins a machine that runs a Hearth agent to a k3s cluster as an agent node, with the join token read from a root-only file on that machine. Rollback runs the k3s uninstaller.

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
#   - Edit the placeholders below (`k3s-new` is the new device, 192.0.2.10 the
#     k3s server, 192.0.2.60 the new node) in every step before you start.
#
# Install and uninstall are exec actions, which are dangerous: they are held or
# denied until the hub grants them, for example:
#   hearth hub --allow-dangerous-automation runbook/add-k3s-node
id: add-k3s-node
description: Join a machine to a k3s cluster as an agent, check it comes up, undo with the k3s uninstaller.
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the agent on the new machine enrolled and allowed to run curl and sh, is the
      join token in /etc/hearth/k3s-token, and are the placeholders in this runbook edited?
    timeout: 30m

  - id: server-up
    type: check
    description: The k3s server's API answers.
    check:
      type: tcp
      address: "192.0.2.10:6443"
    within: 2m
    every: 10s

  - id: fetch-installer
    type: action
    description: Download the k3s install script.
    action:
      type: exec
      device: k3s-new
      command: [/usr/bin/curl, -sfL, -o, /tmp/k3s-install.sh, "https://get.k3s.io"]
      timeout: 2m
    rollback:
      type: exec
      device: k3s-new
      command: [/bin/rm, -f, /tmp/k3s-install.sh]

  - id: install
    type: action
    description: Install k3s as an agent and join the server, reading the token from its file.
    action:
      type: exec
      device: k3s-new
      command:
        - /bin/sh
        - /tmp/k3s-install.sh
        - agent
        - --server
        - "https://192.0.2.10:6443"
        - --token-file
        - /etc/hearth/k3s-token
      timeout: 10m
    rollback:
      type: exec
      device: k3s-new
      command: [/usr/local/bin/k3s-agent-uninstall.sh]
      timeout: 5m

  - id: kubelet
    type: check
    description: The kubelet of the new node answers.
    check:
      type: tcp
      address: "192.0.2.60:10250"
    within: 10m
    every: 10s

  - id: node-ready
    type: prompt
    prompt: confirm
    message: >-
      Does the node show as Ready on the Kubernetes page? Answer no to stop the run,
      then roll back to uninstall k3s. After a rollback, remove the stale Node
      object by hand: kubectl delete node <name>.
    timeout: 30m

  - id: done
    type: action
    action:
      type: log
      message: k3s node joined and confirmed Ready.
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
#   - Edit the placeholders below (`docker-new` is the new device, 192.0.2.70 its
#     address) in every step before you start.
#   - Afterwards, add --allow-restart docker:<container> to the agent for every
#     container Hearth should be able to restart.
#
# The exec actions are dangerous: they are held or denied until the hub grants
# them, for example:
#   hearth hub --allow-dangerous-automation runbook/add-docker-host
id: add-docker-host
description: Install Docker Engine on a machine, start it, verify it, undo with a purge.
steps:
  - id: ready
    type: prompt
    prompt: confirm
    message: >-
      Is the agent on the new machine enrolled and allowed to run the programs listed
      in this runbook, and are the placeholders edited?
    timeout: 30m

  - id: host-up
    type: check
    description: The machine answers on SSH, so it is on the network.
    check:
      type: tcp
      address: "192.0.2.70:22"
    within: 2m
    every: 10s

  - id: fetch-installer
    type: action
    description: Download Docker's convenience install script.
    action:
      type: exec
      device: docker-new
      command: [/usr/bin/curl, -fsSL, -o, /tmp/get-docker.sh, "https://get.docker.com"]
      timeout: 2m
    rollback:
      type: exec
      device: docker-new
      command: [/bin/rm, -f, /tmp/get-docker.sh]

  - id: install
    type: action
    description: Install Docker Engine from Docker's apt repository.
    action:
      type: exec
      device: docker-new
      command: [/bin/sh, /tmp/get-docker.sh]
      timeout: 10m
    rollback:
      type: exec
      device: docker-new
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
      device: docker-new
      command: [/usr/bin/systemctl, enable, --now, docker.service]
      timeout: 2m
    rollback:
      type: exec
      device: docker-new
      command: [/usr/bin/systemctl, disable, --now, docker.service, docker.socket]
      timeout: 2m

  - id: verify
    type: action
    description: Ask the daemon for its version, which fails if it is not running. Changes nothing.
    action:
      type: exec
      device: docker-new
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

Where a step needs something the runbook engine lacks, the recipe uses a prompt for the manual part:

- No variables or inputs for devices, addresses or commands, so addresses are edited in the file.
- No check that a Kubernetes node is Ready, so a prompt asks you to look at the Kubernetes page.
- No action to delete a Node object, so after a rollback you run `kubectl delete node <name>` yourself.
- No Talos integration: Talos is driven through `talosctl` on a device with an agent.
