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
| The CA                | `ca.crt` and `ca.key` (a scheduled backup leaves `ca.key` out by default). Agents trust this CA, and it seals stored kubeconfigs. During a [hub CA rotation](cluster.md#rotating-the-hub-ca) the new CA too (`ca.next.crt`, and `ca.next.key` when `ca.key` is in): both are restored, and a hub restored standalone drops the new one when it starts |
| The database          | Devices, certificates, tokens, audit log, admin password hash, sessions     |
| `policy.yaml`         | If there is one                                                             |
| `notify.yaml`         | Including the credentials in it                                             |
| The automations       | The `.yaml` and `.yml` files the hub loads                                  |
| The runbooks          | The `.yaml` and `.yml` files the hub loads                                  |

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
| `--runbooks-dir`    | The hub runs with `--runbooks-dir` pointing outside the data dir          |

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

## Scheduled backups to S3-compatible storage

The hub can take a backup on its own at a fixed interval and upload it to a bucket on AWS S3 or an
S3-compatible store: MinIO, Garage, Backblaze B2. It keeps the newest backups and deletes older ones.
Scheduled backups are off unless you set `--backup-interval`.

```sh
install -m 600 /dev/null /etc/hearth/backup-passphrase   # then write the passphrase into it
install -m 600 /dev/null /etc/hearth/s3-secret           # and the bucket's secret access key

HEARTH_BACKUP_S3_ACCESS_KEY_ID=hearth-backup \
hearth hub --data-dir /var/lib/hearth/hub \
  --backup-interval 24h --backup-keep 7 \
  --backup-passphrase-file /etc/hearth/backup-passphrase \
  --backup-s3-endpoint https://minio.lan:9000 --backup-s3-bucket hearth-backups \
  --backup-s3-secret-key-file /etc/hearth/s3-secret \
  --backup-notify phone
```

| Flag                         | Environment                          | Default     | Meaning                                                        |
| ---------------------------- | ------------------------------------ | ----------- | -------------------------------------------------------------- |
| `--backup-interval`          | `HEARTH_BACKUP_INTERVAL`             | off         | Time between backups, such as `24h` or `6h`                    |
| `--backup-keep`              | `HEARTH_BACKUP_KEEP`                 | `7`         | How many scheduled backups stay in the bucket                  |
| `--backup-passphrase-file`   | `HEARTH_BACKUP_PASSPHRASE_FILE`      |             | File holding the passphrase, mode `0600`, 12 characters or more |
| `--backup-s3-endpoint`       | `HEARTH_BACKUP_S3_ENDPOINT`          |             | The S3 API URL, `http(s)://host[:port]`                        |
| `--backup-s3-region`         | `HEARTH_BACKUP_S3_REGION`            | `us-east-1` | The bucket's region, used to sign requests                     |
| `--backup-s3-bucket`         | `HEARTH_BACKUP_S3_BUCKET`            |             | The bucket                                                     |
| `--backup-s3-prefix`         | `HEARTH_BACKUP_S3_PREFIX`            | `hearth/`   | Key prefix of the backups                                      |
| `--backup-s3-virtual-host`   |                                      | off         | Address the bucket as `bucket.host` instead of `host/bucket`   |
| `--backup-s3-access-key-id`  | `HEARTH_BACKUP_S3_ACCESS_KEY_ID`     |             | The access key ID                                              |
| `--backup-s3-secret-key-file`| `HEARTH_BACKUP_S3_SECRET_KEY_FILE`   |             | File holding the secret access key, mode `0600`                |
|                              | `HEARTH_BACKUP_S3_SECRET_ACCESS_KEY` |             | The secret access key, instead of the file                     |
| `--backup-include-ca`        | `HEARTH_BACKUP_INCLUDE_CA`           | off         | Put the CA private key into the backups (see below)            |
| `--backup-notify`            | `HEARTH_BACKUP_NOTIFY`               | none        | [Notification channel](notifications.md) told about failures  |

The hub refuses to start when the interval is set and something else is missing, the interval is under
5 minutes, the passphrase is too short, the bucket name breaks the S3 naming rules, or a secret file is
readable by other users.

**Keep the passphrase away from the bucket.** It is read from its file at start and held in memory only.
It is not in the hub's database, in the audit log, in the logs or in the bucket. Anyone who has both a
backup and its passphrase has every credential of the hub, and its CA key with `--backup-include-ca`. The
secret access key is treated the same way. Back the passphrase up somewhere else, such as a password
manager: without it, the bucket holds nothing you can restore.

### The CA key stays out by default

A scheduled backup holds everything a `hearth backup` file holds **except the CA private key**
(`ca.key`): the bucket is a copy of your hub on someone else's disk, and the CA key lets whoever has it
and the passphrase mint certificates every agent trusts. The CA certificate (`ca.crt`) is in.

Restoring such a backup therefore needs the CA key from somewhere else:

- **From a `hearth backup` file.** Take one now and then, and keep it apart from the bucket. The CA
  never changes, so any such backup has the right key, however old it is.
- **Or not at all**, and every agent enrolls again (see [Restoring from the bucket](#restoring-from-the-bucket)).

Start the hub with `--backup-include-ca` (or `HEARTH_BACKUP_INCLUDE_CA=true`) to put the CA key into
the scheduled backups too. A backup from the bucket then restores the hub on its own, as a
`hearth backup` file does. The audit entry of each scheduled backup records whether the key was in
(`ca_key`).

### What the hub does

- Each backup is the encrypted format `hearth backup` writes, without `ca.key` unless
  `--backup-include-ca` is set, named
  `<prefix>hearth-<UTC time>.hbk`, such as `hearth/hearth-20261119T120000Z.hbk`. It is written to a
  working directory in the data dir, uploaded, and deleted locally.
- The first backup is due one interval after the newest backup already in the bucket. A restart, or a new
  leader in a cluster, therefore does not take an extra backup. With an empty bucket the first backup runs
  at start.
- After an upload, the hub deletes all but the newest `--backup-keep` backups under the prefix. It only
  deletes keys that match its own naming exactly, so other objects under the prefix and anything outside
  the prefix are never touched. If the bucket has versioning on, deleted backups stay as noncurrent
  versions until a lifecycle rule removes them.
- Each run is the policy action `hub.scheduled_backup` (dangerous), run by `hub/backup` and audited
  with the bucket, the key, the size, whether the CA key was in, and how many old backups were deleted. It is never held for approval:
  you turned it on with the hub's flags and files, and no one is there to approve each run.
- Uploads are a single `PUT`, so a backup can be at most 5 GiB, far more than a homelab hub's database.

The access key needs only `s3:PutObject`, `s3:ListBucket` and `s3:DeleteObject` on the bucket.

**Give each hub, or each cluster, its own bucket or prefix.** Two hubs that share a bucket and prefix
prune each other's backups.

**Use an `https://` endpoint** unless the store is on the same host. Over plain `http://` the backups
stay encrypted and the secret key is never sent, but anyone on the network path can see each signed
request and send it again for about 15 minutes, including a `DELETE` of a backup.

### When a backup fails

A failed backup or upload is logged as `scheduled backup failed`, recorded in the audit log as
`hub.scheduled_backup` with the result `error: …`, and sent to the `--backup-notify` channel. The message
names the bucket and the error, such as `HTTP 403 AccessDenied`. It never holds the passphrase or the
keys. The hub tries again after the interval or an hour, whichever is shorter.

### In a cluster

Only the leader takes scheduled backups, so there is one backup per interval for the whole cluster. Any
hub can become the leader, so start **every** hub with the same backup flags, and give each one the
passphrase and secret key files.

### Providers

| Provider       | Endpoint                                    | Region                     | Notes                                      |
| -------------- | ------------------------------------------- | -------------------------- | ------------------------------------------ |
| AWS S3         | `https://s3.<region>.amazonaws.com`         | The bucket's region        | `--backup-s3-virtual-host` is recommended  |
| MinIO          | `http(s)://minio.lan:9000`                  | `us-east-1`, unless set    | Path style, the default                    |
| Garage         | `http(s)://garage.lan:3900`                 | Garage's `s3_region`, often `garage` |                                  |
| Backblaze B2   | `https://s3.<region>.backblazeb2.com`       | Such as `us-west-004`      | Use an application key with the S3 API     |

### Restoring from the bucket

Download a backup with any S3 tool, then restore it as any other backup:

```sh
mc cp minio/hearth-backups/hearth/hearth-20261119T120000Z.hbk /tmp/
# or: aws s3 cp s3://hearth-backups/hearth/hearth-20261119T120000Z.hbk /tmp/
hearth restore --data-dir /var/lib/hearth/hub /tmp/hearth-20261119T120000Z.hbk
```

The passphrase is the content of `--backup-passphrase-file`, without the spaces and line breaks around it.

A backup made without `--backup-include-ca` restores everything but `ca.key`, and `hearth restore` says
so. The hub does not start until the key is there (`CA … is incomplete`). Then either:

- **Bring the key back** from a `hearth backup` file: restore that file into an empty temporary dir and
  copy its `ca.key` into the restored data dir, mode `0600`. Start the hub: agents reconnect as after any
  restore.

  ```sh
  hearth restore --data-dir /tmp/hearth-ca /mnt/nas/hearth-2026-01-02.hbk
  install -m 600 /tmp/hearth-ca/ca.key /var/lib/hearth/hub/ca.key
  rm -rf /tmp/hearth-ca
  ```

- **Or start with a new CA**: delete `ca.crt` from the restored data dir. The hub creates a new CA, so
  every browser must trust it again (see [HTTPS](https.md)), every agent has to enroll again with a new
  token, every other hub of a cluster has to join again, and Kubernetes clusters and Proxmox servers have
  to be added again: their credentials are sealed with a key derived from the CA key. The audit log,
  automations and the rest of the configuration are kept. An agent that enrolls again (remove its agent
  data dir, then `hearth agent join` with a new token) becomes a new device; its old entry stays, offline,
  until you revoke it with `hearth device revoke`.

A restored hub shows the scheduled backup it came from as `started` in its audit log, like a backup taken
with `hearth backup`.

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

If the hub ran with `--notify-config`, `--automations-dir` or `--runbooks-dir` outside the data dir, those
files are restored into the data dir as `notify.yaml`, `automations/` and `runbooks/`. Drop the flags, or
move the files back.

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
   If the backup was taken during a [hub CA rotation](cluster.md#rotating-the-hub-ca), finish it now
   (`hearth cluster ca finish`): no hub can join while it is under way.
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

6. **Copy the configuration** to the hubs that joined: `policy.yaml`, `notify.yaml`, the automations
   directory and the runbooks directory are not replicated. `hearth cluster status` shows `in_sync` when they match (see
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
