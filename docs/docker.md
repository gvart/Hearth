---
title: Docker and Podman
description: See a device's containers and Compose stacks, start, stop and restart them, and read their logs.
---

An agent can show its device's Docker or Podman containers, grouped by Compose project ("stacks"),
and its images, and let you start, stop and restart a container or read the last lines of its log.
Open a device and scroll to **Containers**.

## Turn it on, per device

The hub reaches no container until you start the agent with `--allow-docker`:

```sh
hearth agent run --allow-docker
```

The flag is part of the device's [capability ceiling](guardrails.md#device-capability-ceiling): the
hub cannot turn it on from its side, refuses a request to an agent that does not report it, and the
agent refuses it again. `--allow-restart docker:NAME` and `--allow-logs docker:NAME` are separate
and unchanged: they are what automations and the **Logs** section use.

### Which socket

The agent talks to the engine's Docker Engine API over its unix socket. Without `--docker-socket` it
uses the first of these that exists:

1. `/var/run/docker.sock` (Docker)
2. `$XDG_RUNTIME_DIR/podman/podman.sock` (rootless Podman: `systemctl --user enable --now podman.socket`)
3. `/run/podman/podman.sock` (rootful Podman: `systemctl enable --now podman.socket`)

Name another one, such as Colima's or a rootless Docker's, with `--docker-socket`; a `unix://`
prefix, as `DOCKER_HOST` has it, is fine:

```sh
hearth agent run --allow-docker --docker-socket unix:///home/me/.colima/default/docker.sock
```

The agent's user must be able to open the socket: in the `docker` group for Docker, or the user who
runs rootless Podman. Access to the Docker socket is as much as root on the host, which is why the
agent asks the engine for a few things only (below), and why the flag is off by default. A missing
socket, or one nobody listens on, shows as an error in the drawer that names the paths tried.

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
  image with its tags and size. At most 500 of each.
- **Logs**: stdout and stderr with their timestamps, at most the last 200 lines, read once; never a
  follow. Lines are cut at 4 KiB.
- **Stop** gives the container the engine's default 10 seconds to exit before it is killed. A start
  of a running container, or a stop of a stopped one, succeeds and changes nothing.

Every request goes through policy and is audited, reads included: a log may carry secrets. Stopping
and starting are `safe`, as a service restart is; hold them for approval with a policy file such as
`actors: {web: {safe: confirm}}` (see [guardrails.md](guardrails.md)).

## Nothing kept on the hub

The hub asks the agent when you open the drawer, press **Refresh** or take an action, and keeps
nothing: container state never goes into the replicated store, and an agent with `--allow-docker`
holds no connection to the engine between requests. The drawer never polls.

The API, behind an admin session:

- `GET /api/v1/devices/{id}/docker`: stacks, other containers, images
- `GET /api/v1/devices/{id}/docker/logs?container=NAME&tail=N`
- `POST /api/v1/devices/{id}/docker/actions` with `{"action": "restart", "container": "NAME"}`
