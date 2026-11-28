---
title: MQTT broker
description: An MQTT broker built into the hub, over TLS, for enrolled devices and password users, with per-client topic rules and a bridge to another broker.
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

The hub reads the clients file when it starts. Restart it after you change the file. The hub writes
the file itself only to remove a [Device Protocol device](#devices-without-an-agent-the-device-protocol)'s
user. A hub with
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

## Bridge to another broker

If you already run a broker (Mosquitto, EMQX, HiveMQ...), the hub's broker can connect to it as a
client and forward topics in either direction. Start the hub with `--mqtt-bridge` and a bridge
file:

```yaml
# /etc/hearth/mqtt-bridge.yaml
address: broker.lan:8883             # the remote broker, always over TLS
ca_file: /etc/hearth/remote-ca.crt   # CA of its certificate (default: the system's)
client_id: hearth-hub1               # default hearth-<hostname>; one per hub
protocol: 5                          # 5 (default) or 4 for an MQTT 3.1.1 broker
username: hearth
password_file: /etc/hearth/mqtt-bridge.pass   # chmod 600; or HEARTH_MQTT_BRIDGE_PASSWORD
# cert_file: /etc/hearth/bridge.crt  # or a client certificate,
# key_file: /etc/hearth/bridge.key   # its key chmod 600
topics:
  - prefix: sensors/                 # topics under sensors/ on the hub's broker
    remote_prefix: home/sensors/     # are home/sensors/... on the remote (default: the same)
    direction: both                  # in (remote to hub), out (hub to remote) or both
```

```sh
hearth hub --mqtt-listen :8883 --mqtt-bridge /etc/hearth/mqtt-bridge.yaml
```

| Flag | Env | |
| --- | --- | --- |
| `--mqtt-bridge` | `HEARTH_MQTT_BRIDGE` | The bridge file. Needs `--mqtt-listen`. Default: off |
| | `HEARTH_MQTT_BRIDGE_PASSWORD` | The remote password. Wins over `password_file` |

The bridge file holds no secret, and the hub refuses a `password:` in it. The password comes from
`HEARTH_MQTT_BRIDGE_PASSWORD` or from `password_file`, whose first line is the password. The hub
refuses a password file or a client key that group or others can read. It never logs the password.
The remote's certificate is always checked: there is no plain-text or skip-verify mode.

**The bridge is bound by the clients file.** It acts on the hub's broker as a client of its own,
whose rules go in a `bridge` section of the clients file. A message comes in only on a topic the
bridge may `write`, and goes out only from a topic it may `read`. Anything else is dropped and
logged at debug level. Without a `bridge` section the hub refuses to start, since the bridge could
forward nothing.

```yaml
# <data-dir>/mqtt.yaml
bridge:
  allow:
    - topic: sensors/#
      access: readwrite
```

The remote broker's own rules apply too, to the user or certificate the bridge logs in with.

**Loops.** A prefix bridged both ways does not loop. The bridge never sends out a message it brought
in. With MQTT 5 it subscribes with No Local, so the remote does not send back what the bridge
published. An MQTT 3.1.1 broker has no No Local, so the bridge remembers what it sent for 10
seconds and drops the copy that comes back. Each subscriber on either side gets each message once.

**Reconnects.** When the remote goes away, the bridge reconnects with a backoff from 1 second up to
2 minutes, and logs each attempt with its reason. It subscribes again each time, so the remote sends
its retained messages again. A failing remote never stops the hub.

Bridge limits:

- Messages are forwarded at QoS 0, keeping their retain flag. A message sent while the remote is
  unreachable is dropped, as is one that arrives when 256 messages are already waiting to go out.
- MQTT 5 properties, such as user properties or a content type, are not forwarded.
- A packet from the remote may be at most 256 KiB. With MQTT 5 the bridge tells the remote so, and
  it drops larger messages. An MQTT 3.1.1 remote that sends one makes the bridge reconnect.
- One remote broker per hub. Bridge more prefixes by adding entries to `topics`.
- A prefix ends in `/`, has no wildcard, and forwards the topics below it, not the prefix itself.
- The hub reads the bridge file when it starts. Restart it after you change the file.

## Devices without an agent: the Device Protocol

A microcontroller or any small device can join Hearth through the broker with the
[Device Protocol](spec/device-protocol-v1.md): JSON messages on its own topics under
`hearth/v1/<id>/`. It announces itself and shows up with the other devices, reports its state and
readings, and takes the commands it announced. Each command is a policy decision
(`device.command`, dangerous) and audited. Give the device a user of its own, named by its id, and
its topics:

```yaml
users:
  - name: kitchen-sensor
    password_hash: "$2a$10$..."
    allow:
      - topic: hearth/v1/kitchen-sensor/#
        access: readwrite
```

Under `hearth/v1/` the broker lets a client publish only to its own device topics, whatever the
clients file grants, and no client publishes a command: only the hub does. Malformed or oversized
protocol messages (over 16 KiB) are dropped before anyone receives them. A reference client for the
ESP32 is in [examples/esp32](../examples/esp32/README.md).

The device's page in the web UI shows the entities it announced with their latest values, which
update as it reports them, and its telemetry. It has a form for each command the device announced,
with optional params as a JSON object, and shows the device's result. The page has none of an
agent's panels. From the CLI, through the same API and policy:

```sh
hearth device command kitchen-sensor relay.set --param on=true   # prints the device's result
hearth device remove kitchen-sensor
```

`<device>` is the device's ID or its protocol id. A `--param` value that is JSON (`true`, `3`,
`{...}`) is sent as such, anything else as a string. Both commands sign in with the admin password
(`HEARTH_ADMIN_PASSWORD`, or asked for).

**Removing a device** (the Remove device button, or `hearth device remove`) is the policy action
`device.remove`, dangerous: it asks for the admin password again, and it is audited. The hub takes
the device's user out of its clients file, keeping the rest of the file and its comments, and out of
the running broker. That ends the device's connections and refuses its next login. Then the hub
removes the device. To bring it back, give it a user again and restart the hub. In a cluster, each
hub changes only its own clients file. If the device's user is in the file of another hub, remove
it there too, or the device announces itself again. The hub says when its own file had no such user.
An enrolled device is revoked (`hearth device revoke`), not removed.

## What the hub logs

The hub logs every refused connection with its reason, the user or device, the client ID and the
address it came from. It never logs passwords or message payloads. Denied topics are logged at debug
level. MQTT traffic is not written to the audit log: a broker carries far too many messages, and the
clients file is the rule that guards it. Device Protocol commands are the exception: each one the
hub sends is a policy decision, audited. A refused Device Protocol message is logged with its
reason, never its payload.

## Limits

- Messages, retained messages and sessions are kept in memory. They do not survive a hub restart.
- In a [cluster](cluster.md) every hub started with `--mqtt-listen` runs a broker of its own, with
  its own clients file. The brokers do not share messages. Point your devices at one hub.
- A packet, CONNECT included, may be at most 256 KiB. A larger one ends the connection.
- MQTT 5 topic aliases are not supported. A publish that uses one ends the connection.
- Password checks run one at a time. At most 32 logins wait for one, each for up to 2 seconds.
  Beyond that a login is refused as busy, and the client should retry.
