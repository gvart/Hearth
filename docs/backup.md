---
title: Backup and restore
description: Back up a hub to an encrypted file and bring it back, on one hub or a cluster.
---

`hearth backup` writes everything a hub needs to come back into one encrypted file. `hearth restore`
brings it back into an empty data dir. Enrolled agents reconnect by themselves, with the identity they
already have: nothing has to be enrolled again.

## What a backup holds

| Item                  | Notes                                                                       |
| --------------------- | --------------------------------------------------------------------------- |
| The CA                | `ca.crt` and `ca.key`. Agents trust this CA, and it seals stored kubeconfigs |
| The database          | Devices, certificates, tokens, audit log, admin password hash, sessions     |
| `policy.yaml`         | If there is one                                                             |
| `notify.yaml`         | Including the credentials in it                                             |
| The automations       | The `.yaml` and `.yml` files the hub loads                                  |

It does **not** hold:

- **Raft state** (`raft/`: the log, snapshots, node ID and node certificate). A restored hub starts with
  no cluster and no peers.
- **The hub's own host metrics** (`metrics.db`). Charts of the hub start empty after a restore.
- **Files outside the hub's configuration**, such as `--pihole-password-file`, DHCP lease files and
  `--assets-dir`. Keep your hub's start command and these files somewhere else.

## Taking a backup

Run it on the hub host. The hub can keep running: the database copy is taken with SQLite's
`VACUUM INTO`, so it is consistent while writes continue.

```sh
hearth backup /mnt/nas/hearth-$(date +%F).hbk
```

The passphrase is asked for twice on a terminal. For a scheduled job, set `HEARTH_BACKUP_PASSPHRASE`
instead, from a file only that job can read:

```sh
HEARTH_BACKUP_PASSPHRASE="$(cat /etc/hearth/backup-passphrase)" \
  hearth backup /mnt/nas/hearth-$(date +%F).hbk
```

There is no passphrase flag, because other users on the host can read command lines.

| Flag                | Use it when                                                               |
| ------------------- | ------------------------------------------------------------------------- |
| `--data-dir`        | The hub does not use the default data dir (or `HEARTH_DATA_DIR`)          |
| `--notify-config`   | The hub runs with `--notify-config` pointing outside the data dir         |
| `--automations-dir` | The hub runs with `--automations-dir` pointing outside the data dir       |

The file is written with mode `0600` and appears only when it is complete. An existing file is never
overwritten, so give each backup its own name.

A backup is the policy action `hub.backup` (dangerous), run by the local admin and audited like any
other. If your `policy.yaml` holds dangerous actions for approval, the command waits for that approval.
The audit log records the backup before the copy is taken and its outcome afterwards, so a restored hub
shows that backup as `started`. The outcome is on the hub that took it.

### The passphrase

A backup holds the CA private key and every credential of the hub, so it is always encrypted. The
passphrase needs at least 12 characters. **Without it the backup cannot be restored**: there is no
recovery. Keep it apart from the backups, in a password manager for example.

The file is encrypted with AES-256-GCM under a key derived from the passphrase with Argon2id (3 passes,
64 MiB). Any change to the file, including cutting it short, makes the restore fail.

## Restoring a hub

Restore into a data dir that is missing or empty, using the same or a newer Hearth version:

```sh
hearth restore --data-dir /var/lib/hearth/hub /mnt/nas/hearth-2026-11-19.hbk
hearth hub --data-dir /var/lib/hearth/hub --host hub.lan
```

If the hub ran as a service, stop the service before you restore, and run the restore as the user the
service runs as, so that the hub can read the restored files.

**Bring the hub back under the same address.** Agents dial the URL they enrolled with. Use the same
`--host` names and port, or point the old DNS name at the new machine. The hub's certificate is issued
again at every start, from the restored CA, so agents trust it.

If the hub ran with `--notify-config` or `--automations-dir` outside the data dir, those files are
restored into the data dir as `notify.yaml` and `automations/`. Drop the flags, or move the files back.

Restore refuses, and leaves the data dir as it found it, when:

| Message                                  | What to do                                                                       |
| ---------------------------------------- | -------------------------------------------------------------------------------- |
| `the data dir is not empty`              | Choose an empty directory. There is no way to force it, on purpose               |
| `wrong passphrase`                       | Use the passphrase this backup was made with                                     |
| `the backup is corrupted or truncated`   | Use another copy of the backup                                                   |
| `schema version not supported`           | The backup comes from a newer Hearth: install that version or a newer one        |
| `it holds an incomplete restore`         | A restore was killed while moving files. Empty the data dir and restore again    |

A filesystem's `lost+found` counts as content: restore into a subdirectory of such a mount.

### What a restore takes you back to

The hub returns to the moment of the backup. Whatever happened after it is gone:

- **A device revoked after the backup is trusted again.** Run `hearth device revoke` for it once more.
- **A device enrolled after the backup is unknown.** Enroll it again: remove its agent data dir and
  run `hearth agent join` with a new token.
- **Enrollment tokens** created before the backup and not yet expired are valid again until they expire.
- **MCP tokens revoked after the backup work again.** Run `hearth mcp token revoke <name>` for each one
  once more, and check the list with `hearth mcp token list`.
- **Web sessions that ended after the backup work again** until they expire, including sessions you logged
  out of. To end them all, run `hearth admin set-password`: it logs out every session.
- **Approvals that were pending in the backup** have no one waiting for them any more. The restored hub
  expires them, and audits it, once they are five minutes past their expiry, as after any restart (see
  [guardrails](guardrails.md)). The action they held does not run.
- Admin password changes, approvals and audit entries made after the backup are lost.

## Restoring a cluster

A cluster comes back as **one hub that forms a new cluster**, and the other hubs join it again. Hubs
are not restored one by one: their data would be the same, and the Raft history of the old cluster must
not come back.

Back up any member, on the member's host while its hub runs. Writing the audit entry needs the cluster,
so a member without a working majority refuses the backup. Take backups before you need them.

1. **Stop every hub of the old cluster.**
2. **Restore one hub** into an empty data dir:

   ```sh
   hearth restore --data-dir /var/lib/hearth/hub /mnt/nas/hearth-2026-11-19.hbk
   ```

3. **Start it as a new cluster.** Remove `--join` from its start command first, if it has one:

   ```sh
   hearth hub --cluster --host hub-a.lan --advertise hub-a.lan:7444
   ```

   It forms a one-voter cluster from the restored database. `hearth cluster status` shows it alone.
4. **Wipe the other hubs' data dirs.** Each one holds the old cluster's Raft state and a copy of the CA
   key.
5. **Join them again**, one at a time, as in [Forming the cluster](cluster.md#forming-the-cluster):

   ```sh
   hearth cluster token create --hub-url https://hub-a.lan:7443
   # on each other hub, with an empty data dir
   HEARTH_JOIN_TOKEN=hearthj1.… hearth hub --join https://hub-a.lan:7443 \
     --host hub-b.lan --advertise hub-b.lan:7444
   ```

   Every hub must run a Hearth version that supports restored clusters, so use the same version as the
   restored hub. An older hub is refused with a message to upgrade it first, and its join token stays valid.

6. **Copy the configuration** to the hubs that joined: `policy.yaml`, `notify.yaml` and the automations
   directory are not replicated. `hearth cluster status` shows `in_sync` when they match (see
   [Configuration drift](cluster.md#configuration-drift)).

Agents need nothing: they try the hubs they know, and learn the new list once they reach one.

### Why the old hubs cannot interfere

A restored hub has no Raft state, so it knows no peers. The old hubs still hold certificates from the
same CA, though, and one that is still running keeps calling the old members' addresses, including the
address the restored hub now uses.

Every restore therefore starts a new **cluster epoch**: a random value in the `cluster-epoch` file, carried
in the certificates of the restored hub and of every hub that joins it. Hubs of different epochs refuse
each other on the Raft port and on hub-to-hub calls, in both directions. This covers hubs that joined
after the backup, which the backup cannot know about. A restore also revokes every hub certificate
recorded in the backup.

This keeps out hubs that are merely out of date. It is not a defence against a hostile hub: every voter
of the old cluster holds the CA key, which is why step 4 matters. If those hubs might be compromised,
start over with a new CA instead of restoring this one.
