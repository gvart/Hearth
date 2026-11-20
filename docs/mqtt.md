---
title: MQTT broker
description: An MQTT broker built into the hub, over TLS, for enrolled devices and password users, with per-client topic rules.
---

The hub can run an MQTT broker of its own ([mochi-mqtt](https://github.com/mochi-mqtt/server)), so
sensors, smart plugs, ESPHome or Tasmota devices and your scripts have somewhere to publish without a
separate Mosquitto. It is off by default. When it is on:

- Clients connect over **TLS only**, with the hub's own certificate (from the hub CA, see
  [HTTPS](https.md)). There is no plain-text port.
- Every client authenticates, with an **enrolled device's client certificate** or a **username and
  password**. There is no anonymous access.
- Every topic a client publishes or subscribes to must be **granted to it**. Anything else is
  denied.

## Turn it on

1. Write the clients file, `<data-dir>/mqtt.yaml` by default. Only the hub's user should be able to
   read it (`chmod 600`). It holds password hashes, and the hub warns at start if others can read it. The hub refuses to
   start if group or others can write it, since whoever can write it can grant themselves any topic.

   ```yaml
   users:
     - name: sensors
       password_hash: "$2a$10$..."   # from `hearth mqtt hash-password`
       allow:
         - topic: sensors/#
           access: readwrite
     - name: dashboard
       password_hash: "$2a$10$..."
       allow:
         - topic: sensors/#
           access: read
   devices:
     - id: cdb1a1c4399bb039bdc3       # an enrolled device, by its device ID
       allow:
         - topic: hearth/cdb1a1c4399bb039bdc3/#
           access: readwrite
   ```

2. Hash each user's password. The command reads it without echo, or as the first line of stdin, and
   prints the hash. It never stores or logs the password.

   ```sh
   hearth mqtt hash-password
   ```

3. Start the hub with an MQTT address. 8883 is MQTT's usual TLS port.

   ```sh
   hearth hub --mqtt-listen :8883
   ```

| Flag | Env | |
| --- | --- | --- |
| `--mqtt-listen` | `HEARTH_MQTT_LISTEN` | Address to serve MQTT over TLS on, e.g. `:8883`. Default: off |
| `--mqtt-clients` | `HEARTH_MQTT_CLIENTS` | The clients file. Default `<data-dir>/mqtt.yaml` |

The hub reads the clients file when it starts. Restart it after you change the file. A hub with
`--mqtt-listen` and no clients file, or with an invalid one, refuses to start.

## Connect

Clients verify the hub with its CA certificate, served at `http://<hub>:7080/ca.crt`. Connect to a
name the hub's certificate carries (its `--host` names).

With a username and password:

```sh
curl -o hearth-ca.crt http://hub.lan:7080/ca.crt
mosquitto_sub -h hub.lan -p 8883 --cafile hearth-ca.crt -u sensors -P '...' -t 'sensors/#' -v
mosquitto_pub -h hub.lan -p 8883 --cafile hearth-ca.crt -u sensors -P '...' -t sensors/kitchen/temp -m 21.5
```

With a device's client certificate: an enrolled device already has one, from `hearth agent join`. It
is in the agent's data dir, `agent.crt` and `agent.key`. List the device's ID under `devices`:

```sh
mosquitto_sub -h hub.lan -p 8883 --cafile /var/lib/hearth/agent/ca.crt \
  --cert /var/lib/hearth/agent/agent.crt --key /var/lib/hearth/agent/agent.key -t 'sensors/#' -v
```

When a client presents a certificate, the certificate decides who it is. A username, if it sends
one, must be the device ID, and a password is ignored. The hub checks the certificate is one it
issued to that device and has not revoked (`hearth device revoke`), as it does for the agent. It
checks the certificates of connected devices again every 30 seconds. A device whose certificate has
been revoked, or was issued by a hub CA that a [CA rotation](cluster.md) has retired, is disconnected.

## Topic rules

Each rule grants `read`, `write` or `readwrite` on the topics an MQTT topic filter matches:

- `sensors/#` matches `sensors` and everything below it.
- `home/+/temperature` matches one level in place of `+`.
- `#` matches every topic except those starting with `$`, such as `$SYS/...`. Grant `$SYS/#`
  explicitly to read the broker's statistics.

`read` lets a client subscribe to a filter only if a rule covers all of it. A client allowed
`sensors/#` may subscribe to `sensors/+/temp` but not to `#`. The hub also checks every message it
delivers. `write` lets a client publish to a topic, and set it as its will (last-will) topic. A
client whose will topic it may not write is refused at connect.

What happens on a denied publish depends on the client's MQTT version and QoS. At QoS 0 the message
is dropped silently. At QoS 1 or 2 an MQTT 5 client is told "not authorized" and an MQTT 3.1.1
client is disconnected. A denied subscription is answered with a failure code.

A client ID belongs to the client that holds its session. A client of another user or device that
connects with that ID is refused.

## What the hub logs

The hub logs every refused connection with its reason, the user or device, the client ID and the
address it came from. It never logs passwords or message payloads. Denied topics are logged at debug
level. MQTT traffic is not written to the audit log: a broker carries far too many messages, and the
clients file is the rule that guards it.

## Limits

- Messages, retained messages and sessions are kept in memory. They do not survive a hub restart.
- In a [cluster](cluster.md) every hub started with `--mqtt-listen` runs a broker of its own, with
  its own clients file. The brokers do not share messages. Point your devices at one hub.
- A packet, CONNECT included, may be at most 256 KiB. A larger one ends the connection.
- MQTT 5 topic aliases are not supported. A publish that uses one ends the connection.
- Password checks run one at a time. At most 32 logins wait for one, each for up to 2 seconds.
  Beyond that a login is refused as busy, and the client should retry.
- Bridging to another broker is not built in yet ([#221](https://github.com/gvart/hearth/issues/221)).
