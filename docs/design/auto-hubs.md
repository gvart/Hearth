# Auto hubs: a capable device becomes a hub when it is installed

**Status:** decided 2026-11-22 by the owner for #328 (owner decisions below amend the proposal). Related: #329 (`hearth.local`), #330 (safe to stop), #331 (remove
dead members, keep 3 masters).

## Goal

Run `hearth hub` on a laptop, paste the Add device command on two to four devices, stop the laptop.
The devices carry on as the cluster. No flags at install.

## Owner decisions (amend the proposal below)

- "May become a hub" in Add device is on by default, and ticking it needs the password again
  (`recentAuth`), as Add hub does. The API field `hub` defaults to false; the dialog sends true.
  CLI: `hearth token create --hub`.
- **Linux only** qualifies automatically (amd64/arm64, MemTotal ≥ 1536 MiB, ≥ 2 GiB free on the hub
  data dir's filesystem). macOS never offers; a later per-device toggle (#332) covers it.
- **Caps: at most 3 masters and at most 5 storage members.** A capable device beyond the master cap
  becomes storage only; beyond the storage cap it stays an agent (no `hub_join`). The storage cap is
  checked first: with 5 storage members counted no device is offered a hub, however few masters
  there are. Both caps are checked again in `cluster.Join`, where the key leaves: past the master
  cap a minted token grants storage only (`capped: true`); past the storage cap the join is refused
  for good, the device deletes its join file and stays an agent.
- The minted join token is audited as `cluster.token.create` with actor kind `token`; the CA key
  travels only over the existing `cluster.Join` channel.
- A joining hub learns the master's advertised gossip address (and the other members') from the
  join response and keeps them in `cluster/gossip-seeds`, so a hub joined with only `--join` or a
  join file meets the cluster even when the join URL's host is not its gossip address (#334).

## Decisions (proposal)

### 1. Consent: the admin grants it at Add device

- The Add device dialog gains **"This device may become a hub"**, on by default: "a capable device
  stores a copy of the data and, while there are fewer than 3 masters, becomes a master and holds
  the CA key". `POST /api/v1/tokens` takes `"hub": true` (default false, so existing callers are
  unchanged; the dialog sends true unless unticked); `hearth token create --hub` for CLI parity.
- Such a token hands the CA key to whoever redeems it, so its creation is decided twice, nested,
  before anything is written: `token.create` (safe), then `cluster.token.create` (dangerous,
  `Precheck: a.recentAuth(r)`, held or denied by the policy modes, as for Add hub). The admin enters
  the password again. Its detail is `{via: "enrollment_token", roles, ttl, token: <handle>}`; the
  handle, `tokenActorID(secret)`, is the actor id of the later `device.enroll` entry.
- Migration **00034**: `tokens.hub_roles TEXT NOT NULL DEFAULT ''` and `join_tokens.device_id TEXT
  NOT NULL DEFAULT ''` (the device a join token was minted for). `CreateToken` and `CreateJoinToken`
  carry them `omitempty`; writing either needs schema 34 (`hubTokenSchema`, gated like
  `tokenNameSchema`), else Add device answers 409 `schema_too_old`.

### 2. The device is the ceiling

- Only the installer offers a hub: `install.sh` runs `hearth agent join --hub-data-dir
  /var/lib/hearth/hub`. Without that flag (a manual `agent join`, the Kubernetes DaemonSet; an
  upgrade re-run never enrolls) nothing is offered. `install.sh --agent-only` (env
  `HEARTH_AGENT_ONLY=1`) opts out.
- **Capable** (`cluster.HubCapable`, checked by the agent before offering and again by the hub):
  `runtime.GOOS` linux or darwin, `runtime.GOARCH` amd64 or arm64, MemTotal ≥ 1536 MiB (a 2 GB board
  reports about 1.8 GiB; 1 GB boards do not qualify), ≥ 2 GiB free on the hub data dir's filesystem.
  No flags. The lab's Pi 4 (7819 MiB, 20 GB free) and Pi 5 (16218 MiB, 93 GB) qualify.
- `EnrollRequest` gains `HubOffer hub_offer` (`os`, `arch`, `mem_total`, `disk_free`).

### 3. Enrollment mints a join token; the existing join carries the CA key

On the master owning the enrollment token, once `device.enroll` has succeeded:

1. No hub without the token's `hub_roles`, an offer, or a passing `HubCapable`; the `device.enroll`
   detail says which (`hub: "not eligible" | "not offered" | "not capable"`), or, for a capable
   device, the mint's outcome (`hub: "minted"` with `hub_roles`, or `hub: "refused"` with
   `hub_refused`).
2. Roles: `storage`, plus `master` while fewer than 3 masters are counted: members with the master
   role that are not `left` (a dead one counts until removed), plus the unspent join tokens minted
   with master, plus the hubs that joined with a minted token in the last 10 minutes, hold an
   unrevoked hub certificate and are not in the gossip yet (`join_tokens.joined_node`).
3. A join token is minted (`store.JoinTokens().Create`, TTL 15 min, `device_id` set) as its own
   decision: `cluster.token.create`, actor kind `token`, actor id the enrollment token's handle,
   detail `{roles, device_id}`. The rule becomes `{Dangerous, [admin, web, token], fixedFor:
   [token]}`: never held (the admin decided at Add device), refused while cut off. No web actor is
   recorded without a web request. If the mint fails the device stays an agent, and says why.
4. `EnrollResponse` gains `HubJoin hub_join` (`url`: this master's agent URL, `token`, `roles`, or
   `refused`), over the channel pinned by the token's CA fingerprint.

The device then runs the existing `cluster.Join`: same RPC, pinned TLS, `cluster.join` entry, CA key
only when granted master. No new channel. `APJoinServer.Join` re-checks the cap where the key
leaves: a token with a `device_id` grants `storage` only once 3 masters are counted, the joiner
excluded (`capped: true`). Two enrollments on two masters at once can still make a fourth master:
accepted (two consents, one more key copy).

The node ID is `cluster.NodeID`'s default (hostname plus a random suffix): two `raspberrypi` boards
never collide. The hub keeps the default `--allow-roles storage,master`, so a storage-only auto hub
can be promoted later (by hand, or #331 D2).

### 4. Process model: a second service, the agent unchanged

- The hub is its own service, `hearth-hub.service` (`deploy/systemd`) or `dev.hearth.hub`
  (`deploy/launchd`), data dir `/var/lib/hearth/hub`. The agent and its idle RSS are untouched.
- `ExecStart=hearth hub --data-dir /var/lib/hearth/hub --join-file /var/lib/hearth/hub/join`;
  `agent join --hub-data-dir` writes that file (0600, `{url, token}`).
- `--join-file` means "a member, never a new cluster". With no CA the hub joins with the file and
  deletes it once the join succeeds or is refused for good; with neither CA nor file it logs why and
  exits 0, never creating a CA. A transient failure keeps the file and exits non-zero (systemd
  `Restart=on-failure`, launchd `KeepAlive.SuccessfulExit=false`) until the token expires.
  `cluster.Join` writes `ca.crt` last: present means joined. A node certificate without `ca.crt`
  (crash mid-join) is deleted with the join file, and the hub says to install with a new command.
- systemd also guards it: `ConditionPathExists=|…/hub/join` and `ConditionPathExists=|…/hub/cluster/node.crt`.
- `install.sh` starts the hub, waits up to 60 s for `hearth cluster status` to answer (a storage-only
  member serves no port 7080), then the agent. A failed hub leaves a working agent and a warning.
  `--uninstall` removes both services; `--purge` the hub data dir too.
- **Agents learn new masters on the stream.** Today they learn them only at enrollment and on
  connect, so an agent streaming to the laptop since before d1 existed is stranded when it stops. A
  master now sends `Hubs` on every stream when its ring changes (`MasterRing.Subscribe`); the agent
  merges it into `hubs`.

### 5. Addresses, no flags

Without `--host`, a hub's certificate names its hostname, LAN IPs, loopback (`defaultHubHosts`) and
`hearth.local` (#329); its agent URL is its first LAN IP. The **cluster advertise address** follows,
on every hub including the first: without `--cluster-advertise` it is the first `--host`, else the
first `discovery.LANAddrs` address, else today's `dialableHost`. `docs/cluster.md` "Ports and names"
changes with it.

## How the story ends

Laptop, d1, d2: three masters, three storage members, N = 2. Every row has a copy off the laptop
once d1 and d2 stop `syncing` (#330 shows it). Members remember each other (`cluster/gossip-seeds`),
so d1 and d2 find each other after a reboot without the laptop.

- **Ctrl-C**: the hub leaves the gossip (`left`) and no longer counts for N or the master cap. Two
  masters go on; the next capable device becomes the third. Even one device carries on (N = 1).
- **Killed or asleep**: the laptop is `dead` and still counts. With two devices, critical writes keep
  W = 2 and agents move within about 10 s; the next device is storage only until #331 removes the
  laptop and restores 3 masters. With **one** device, critical writes (login, tokens, enrollments)
  answer 503 until the laptop is back or removed. Getting started says so.
