---
title: Proxmox VE
description: Adopt a Proxmox VE server with an API token, see its hosts, VMs, LXCs and storage, and start, stop or reboot guests.
---

Hearth adopts an existing Proxmox VE server or cluster through an API token. Nothing is installed on
the server. Hearth reads hosts, VMs, LXC containers and storage, and writes only when you start, stop
or reboot a guest.

> **Not yet tested on a real server.** This integration has been tested against a mock of the Proxmox
> VE API, written from the official API documentation. It has not been run against a real Proxmox VE
> server yet.

## Create an API token

Hearth authenticates with an API token only: it does not accept a username and password. Give the
token its own role with the four privileges it needs, and nothing else:

| Privilege         | Path        | Used for                                              |
| ----------------- | ----------- | ----------------------------------------------------- |
| `Sys.Audit`       | `/nodes`    | Reading the status and usage of hosts                 |
| `VM.Audit`        | `/vms`      | Listing VMs and LXCs                                  |
| `Datastore.Audit` | `/storage`  | Listing storage                                       |
| `VM.PowerMgmt`    | `/vms`      | Start, stop and reboot. Leave it out to only read     |

On a Proxmox VE host, as root:

```sh
pveum role add HearthOperator --privs "Sys.Audit VM.Audit Datastore.Audit VM.PowerMgmt"
pveum user add hearth@pve
pveum user token add hearth@pve hub --privsep 1
pveum acl modify / --users hearth@pve --roles HearthOperator
pveum acl modify / --tokens 'hearth@pve!hub' --roles HearthOperator
```

`pveum user token add` prints the secret once. The token Hearth needs is
`hearth@pve!hub=<secret>`. A token with privilege separation (`--privsep 1`) holds only what both it and
its user were granted, which is why the role is assigned twice. To limit Hearth to some guests, grant
the role on a narrower path, such as `/vms/100` or a `/pool/<name>`. Guests the token may not audit do
not appear at all.

## Add the server

In the UI, open **Proxmox** and **Add server**, then enter a name, the address
(`https://pve.lan:8006`; the port defaults to 8006), the token, and how to verify the server's
certificate. TLS verification is always on, and there is no option to turn it off. Plain `http://` is
refused, because the token would travel in the clear. Proxmox VE usually has a self-signed certificate,
so choose one of:

| Verify with            | Enter                                       | Notes                                                                 |
| ---------------------- | ------------------------------------------- | --------------------------------------------------------------------- |
| Its SHA-256 fingerprint | The fingerprint of the certificate it serves | Pins that one certificate. Update it when the certificate is renewed  |
| A CA certificate       | `/etc/pve/pve-root-ca.pem`                  | The address must be a name or IP the server's certificate lists       |
| The hub's system CAs   | Nothing                                     | For a certificate from a public CA, such as one issued through ACME   |

To print the fingerprint on a Proxmox VE host:

```sh
openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256
```

If the node serves a custom certificate, use `/etc/pve/local/pveproxy-ssl.pem` instead. In a cluster,
each node has its own certificate: pin the node whose address you entered.

## What you see

The **Proxmox** page has three tabs, refreshed every few seconds. The hub reads each server every 15
seconds, and right after an action.

- **VMs and LXCs**: every guest with its status, node, CPU, memory and uptime. Templates are left out,
  because they cannot run.
- **Hosts**: every node with its status, CPU, memory, disk and uptime.
- **Storage**: every storage as each node sees it, with its type, content and usage.

A server that cannot be reached, or that refuses the token, shows as **Unavailable** with the reason,
and Hearth keeps trying. Its guests are not shown while it is unavailable, because what was read
earlier may no longer be true. An unreachable server never stops the hub from starting.

## Actions

A running guest has **Stop** and **Reboot**, a stopped guest has **Start**. The UI asks to confirm each
one, and they are also available as `POST /api/v1/proxmox/servers/{id}/actions` with
`{"action": "start", "vmid": 100}`.

| Action | Policy action          | Class     | Proxmox VE API call                                 | What it does                                                 |
| ------ | ---------------------- | --------- | --------------------------------------------------- | ------------------------------------------------------------ |
| Start  | `proxmox.guest.start`  | safe      | `POST /nodes/{node}/{qemu,lxc}/{vmid}/status/start`  | Starts the guest                                             |
| Stop   | `proxmox.guest.stop`   | dangerous | `POST /nodes/{node}/{qemu,lxc}/{vmid}/status/stop`   | Stops it at once, like pulling the plug. Data can be lost    |
| Reboot | `proxmox.guest.reboot` | dangerous | `POST /nodes/{node}/{qemu,lxc}/{vmid}/status/reboot` | Shuts it down and starts it again                            |

- **Policy decides first.** Every action goes through [policy](guardrails.md) and is in the audit log.
  A denied action never reaches Proxmox VE. With `classes: {dangerous: confirm}` in `policy.yaml`, a
  stop or reboot waits on the **Approvals** page and is sent only once approved.
- **Accepted, not finished.** Proxmox VE runs an action as a task. Hearth reports that the server
  accepted it, and the guest's status changes on a later read.
- **The hub picks the node.** A request names only the guest's VMID. The hub looks up its node and kind
  in what it last read from the server.
- **An approval covers one guest.** If the VMID names a guest of another kind or name by the time an
  action is approved, Hearth refuses it and sends nothing. A guest that only migrated is still acted on,
  and the audit log records the node actually used.
- **Web UI only, for now.** Automations and MCP clients cannot take these actions, and hosts themselves
  cannot be rebooted or shut down from Hearth.

Adding and removing a server (`proxmox.server.add`, `proxmox.server.remove`, both safe) are policy
actions too.

## How it works

- **Stored encrypted.** The address, token and trust anchor are sealed with AES-256-GCM before they
  reach the database, so the database, the Raft log and snapshots only ever hold ciphertext. The key is
  derived (HKDF-SHA256) from the hub CA's private key, and is separate from the key that seals
  kubeconfigs. The token never appears in the audit log, the hub log or the API, and is not shown again
  after it is added. To replace it, remove the server and add it again.
- **Every hub reads.** In a hub cluster each hub reads every Proxmox VE server itself and serves its own
  UI. The state is a cache of the Proxmox VE API and is never written to the hub database.
- **One request.** Each read is a single `GET /cluster/resources`, which still answers when a node of
  the Proxmox VE cluster is down. Requests time out after 15 seconds, and redirects are not followed.

On a hub cluster upgraded from an older version, run `hearth cluster migrate` before adding a server
(the table arrives with schema 15).
