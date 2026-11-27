---
title: Docker and Podman
description: See a device's containers and Compose stacks, start, stop and restart them, and read their logs.
---

An agent can show its device's Docker or Podman containers, grouped by Compose project ("stacks"),
and its images, and let you start, stop and restart a container or read the last lines of its log.
Open a device and scroll to **Containers**.

## Turn it on, per device

The hub reaches no container until you turn **Containers** on in the device's **Capabilities**
card: **Read** lists them and reads their logs, **Control** also starts, stops and restarts them (it
asks for your password again). From a hub host:

```sh
hearth device capabilities <device-id> --set docker=read      # or docker=on for control
```

It is part of the device's [capability ceiling](guardrails.md#device-capability-ceiling): the hub
refuses a request to an agent that does not report it, and the agent refuses it again. The agent's
own `--allow-docker` flag grants control from the device. **Restart services** and **Logs**
(`docker:NAME` entries) are separate: they are what automations and the **Logs** section use.

### Which socket

The agent talks to the engine's Docker Engine API over its unix socket. Without `--docker-socket` it
uses the first of these that exists:

1. `/var/run/docker.sock` (Docker)
2. `$XDG_RUNTIME_DIR/podman/podman.sock` (rootless Podman: `systemctl --user enable --now podman.socket`)
3. `/run/podman/podman.sock` (rootful Podman: `systemctl enable --now podman.socket`)

Name another one, such as Colima's or a rootless Docker's, with `--docker-socket`; a `unix://`
prefix, as `DOCKER_HOST` has it, is fine:

```sh
hearth agent run --docker-socket unix:///home/me/.colima/default/docker.sock
```

The agent's user must be able to open the socket: in the `docker` group for Docker, or the user who
runs rootless Podman. Access to the Docker socket is as much as root on the host, which is why the
agent asks the engine for a few things only (below), and why the flag is off by default. A missing
socket, or one nobody listens on, shows as an error on the device's page that names the paths tried.

## What the hub can do

| Request | Engine API | Policy action | Class |
| --- | --- | --- | --- |
| List containers and images | `GET /containers/json?all=1`, `GET /images/json` | `device.docker.list` | `read` |
| Last lines of a container's log | `GET /containers/{id}/logs` | `device.docker.logs` | `read` |
| Start a container | `POST /containers/{id}/start` | `device.docker.start` | `safe` |
| Stop a container | `POST /containers/{id}/stop` | `device.docker.stop` | `safe` |
| Restart a container | `POST /containers/{id}/restart` | `device.docker.restart` | `safe` |

Nothing else of the API is reachable through Hearth: no exec, create, remove, pull, or passthrough
of any other path. Docker and Podman both serve these endpoints. A container is named by its id or
name, letters, digits, `_`, `.` and `-` only, so no request can add a path or a query to the URL.

- **List**: every container, running or not, with its image, state, status and Compose project and
  service (the `com.docker.compose.project` and `com.docker.compose.service` labels), and every
  image with its tags and size. At most 500 of each and about 1 MiB in all; each name, label and
  tag is cut at 256 bytes, and an image lists at most 16 tags. The agent reads the engine's answer
  one entry at a time and stops there, so a huge engine costs it little.
- **Logs**: stdout and stderr with their timestamps, at most the last 200 lines, read once; never a
  follow. Lines are cut at 4 KiB.
- **Stop** gives the container the engine's default 10 seconds to exit before it is killed. A start
  of a running container, or a stop of a stopped one, succeeds and changes nothing.

Every request goes through policy and is audited, reads included: a log may carry secrets. Stopping
and starting are `safe`, as a service restart is; hold them for approval with a policy file such as
`actors: {web: {safe: confirm}}` (see [guardrails.md](guardrails.md)).

## Nothing kept on the hub

The hub asks the agent when you open the device's page, press **Refresh** or take an action, and keeps
nothing: container state never goes into the replicated store, and an agent with Containers on
holds no connection to the engine between requests. The page never polls.

The API, behind an admin session:

- `GET /api/v1/devices/{id}/docker`: stacks, other containers, images
- `GET /api/v1/devices/{id}/docker/logs?container=NAME&tail=N`
- `POST /api/v1/devices/{id}/docker/actions` with `{"action": "restart", "container": "NAME"}`

An AI assistant takes the same requests through the MCP tools `list_containers`, `container_logs`
and `container_action` (see [mcp.md](mcp.md)), as `mcp/<token name>`, within the same ceiling.
