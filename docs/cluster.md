# Running a 3-hub cluster

A single hub is the default, and it needs none of this. A cluster of 3 hubs keeps Hearth running when
any one of them dies: enrollment, the UI, the CLI and agent connections move to the surviving hubs
within seconds, and no committed write is lost. The design is in
[design/ha-hub.md](design/ha-hub.md); this page is the operator's view.

Run 3 hubs (or 5, which survives 2 failures). Two hubs are no better than one: losing either loses the
majority, and the cluster stops accepting writes.

## How it works, in one paragraph

The hubs replicate their database with Raft. One hub is the **leader**; the others are **followers**.
Agents stream to the leader only. The UI, the API and the CLI work on every hub: reads come from the
hub's own copy, and writes made on a follower are forwarded to the leader. If the leader dies, the
others elect a new one in a few seconds, agents reconnect to it, and everything carries on.

## Ports and names

Each hub uses three ports. The defaults are below; all hubs must be reachable from each other on
the Raft port, and from agents and browsers on the TLS port.

| Port | Flag            | Used by                                                       |
| ---- | --------------- | ------------------------------------------------------------- |
| 7443 | `--listen`      | agents, the HTTPS UI and API, and hub-to-hub joins and writes |
| 7080 | `--http-listen` | the plain HTTP UI and API, the installer, `/ca.crt`           |
| 7444 | `--raft-listen` | Raft between hubs (mutual TLS with hub certificates)          |

Give each hub its name with `--host`: the **first** `--host` is the name agents and the other hubs use
to reach that hub's TLS port, so it must resolve from your devices. `--advertise host:7444` is the
address the other hubs dial for Raft (default: this machine's hostname).

## Forming the cluster

On the first hub, with or without existing data (its devices, tokens and password are kept):

```sh
hearth hub --cluster --host hub-a.lan --advertise hub-a.lan:7444
```

`--cluster` is remembered in the data dir; later starts need no flag. Then create one join token per
new hub, on any member's host while its hub runs:

```sh
hearth cluster token create --hub-url https://hub-a.lan:7443
```

The token is single use and short lived. It hands the new hub the cluster's CA, private key included,
so treat it like the CA key. On each new hub, with an **empty** data dir:

```sh
HEARTH_JOIN_TOKEN=hearthj1.… hearth hub --join https://hub-a.lan:7443 \
  --host hub-b.lan --advertise hub-b.lan:7444
```

The new hub pins the CA by the fingerprint in the token, joins as a non-voter, receives a copy of the
database, and promotes itself to a voter once it runs. Use the same Hearth version on every hub: a
hub with a different database schema is refused.

## Checking on it

```sh
hearth cluster status          # on any member's host
hearth cluster status --json
```

It shows this hub's state, the leader, the Raft term and indexes, and every peer with its suffrage.
All peers should be `Voter`. In the hub logs, `leading the cluster` and `no longer leading the
cluster` mark leadership changes, and `caught up with the cluster` marks a hub that is ready after a
start.

## What happens when a hub fails

- **A follower dies.** Nothing visible happens. When it comes back it catches up from the leader.
- **The leader dies.** The remaining hubs elect a new leader within a few seconds. Agents notice their
  stream ended, try the other hubs they know, and are sent on to the new leader; expect them back
  within about 10 seconds. Devices stay online in the UI: a new leader counts every online device as
  seen when it took over and only marks one offline if it stays silent for the full offline timeout
  (30 s) after that.
- **Leadership moves while the leader is still alive** (for example after a network hiccup). The old
  leader ends every agent stream with a "not the leader" answer naming the new one, and the agents go
  there at once.
- **Two of three hubs are down.** There is no majority, so there is no leader. Reads still work on the
  surviving hub, with the data it had. Every write (logging in, creating a token, enrolling, an agent
  coming online) waits up to 5 seconds for a leader and then fails with HTTP 503
  `cluster_unavailable` (or a "cluster unavailable" CLI error); nothing is written. Agents keep
  retrying. Bring a second hub back and everything resumes.
- **A hub restarts.** Until it has caught up with the cluster, its API waits up to 5 seconds per
  request and then answers 503 `catching_up`; the UI shows the error and works again once the hub is
  ready, usually within a second or two.

CI holds the cluster to these: an end-to-end test (`task e2e:cluster`, in
[`test/e2e/cluster_test.go`](../test/e2e/cluster_test.go)) runs three hubs and an agent in Docker
Compose, kills the leader, takes the majority away and back, and fails if any step takes longer
than its stated bound.

## The UI on any hub

Open `https://<any hub>:7443` (or `http://<any hub>:7080`). Logins, token creation and everything else
work on every hub; on a follower, the write is forwarded to the leader. Sessions are replicated, but
cookies belong to a host name: switching from `hub-a.lan` to `hub-b.lan` means logging in again.
Give all hubs one shared DNS name (several A records) if you want one login to survive a failover.

Live updates (the device list changing as devices come and go) are pushed by the leader. A UI open on
a follower shows the replicated state when it loads or refreshes, and the last-seen time it shows can
trail the leader's by up to 30 seconds, because the leader writes last-seen times in batches
([#27](https://github.com/gvart/hearth/issues/27) tracks live updates on followers).

## Agents

Nothing to configure. An agent joins through any hub (a follower sends it to the leader), receives
the list of every hub's URL, keeps it in `hubs` in its data dir, and refreshes it on every connection.
When its hub goes away it tries the others in turn.

## CLI on a member's host

`hearth token create`, `hearth device revoke`, `hearth admin set-password` and
`hearth cluster token create` work on any member while its hub runs: they go through the hub's local
control socket and, on a follower, on to the leader. With the hub stopped they refuse, since writing
the local database directly would diverge from the cluster.

## Policy and audit

Every action is decided and audited by the hub that received the request, exactly as on a single
hub. A forwarded write is replication only: the follower authenticates to the leader with its own
hub node certificate (never with a device or admin credential), and the leader applies the command
without a second decision. The audit entry is itself a write through the same path, so it lands in
the replicated log in order with the action.

## Limits

- **No member removal yet** ([#29](https://github.com/gvart/hearth/issues/29)). A hub that is gone
  for good still counts towards the majority; a 3-hub cluster with one dead member tolerates no
  further failure. Rebuilding a hub means a fresh data dir and a new join (with a new node ID).
- **No rolling schema upgrades yet** ([#25](https://github.com/gvart/hearth/issues/25)): upgrade all
  hubs to the same version together.
- All hubs share one CA, and every voter holds its key. Protect each hub's data dir accordingly.
- Clusters of 3 or 5 voters only; no read-only replicas.
