---
title: Device Protocol v1
description: How a microcontroller or any small device joins Hearth over MQTT with JSON messages, no Hearth firmware needed - announce, state, telemetry, availability and commands.
---

<!-- SPDX-License-Identifier: CC-BY-4.0 -->

The Hearth Device Protocol lets any device that can speak MQTT over TLS and write a little JSON
appear in Hearth: an ESP32, an ESP8266, a Raspberry Pi Pico W, or a script. The device announces
itself, reports its state and readings, and takes commands. Hearth shows it with the other devices,
keeps it online while it is connected, and sends it a command only after policy allows it, with an
audit entry for every command.

This document is the protocol's specification. It is licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), so you can implement it in any firmware
under any licence. A reference client for the ESP32 is in
[examples/esp32](../../examples/esp32/README.md). The broker the protocol runs on is described in
[MQTT broker](../mqtt.md).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Overview

```
device                                  hub (embedded MQTT broker, TLS)
  │ CONNECT  user=<id> password=...  will: hearth/v1/<id>/availability {"status":"offline"}
  │ SUBSCRIBE hearth/v1/<id>/command
  │ PUBLISH  hearth/v1/<id>/availability  {"v":1,"status":"online"}       (retained)
  │ PUBLISH  hearth/v1/<id>/announce      {"v":1,"name":...,"entities":[...],"commands":[...]}  (retained)
  │ PUBLISH  hearth/v1/<id>/state         {"v":1,"state":{"relay":false}} (retained)
  │ PUBLISH  hearth/v1/<id>/telemetry     {"v":1,"values":{"rssi":-61}}
  │                                          ◄── policy decides device.command, audits it
  │ ◄─────── hearth/v1/<id>/command       {"v":1,"id":"…","command":"relay.set","params":{"on":true}}
  │ PUBLISH  hearth/v1/<id>/result        {"v":1,"id":"…","ok":true,"message":"relay on"}
```

## Identity and authentication

A device connects to the hub's embedded MQTT broker over TLS (port 8883 by default), and checks the
hub's certificate against the hub CA, served at `http://<hub>:7080/ca.crt`. There is no plain-text
port and no anonymous access.

In v1 a device authenticates with a **per-device MQTT username and password**: a user of the hub's
MQTT clients file (`<data-dir>/mqtt.yaml`). The username is the device's **id**. An id is 1 to 64
characters of lowercase ASCII letters, digits, `_` and `-`, starting with a letter or a digit, such
as `kitchen-sensor`. Give each device its own user and password: the broker lets a device use only
the topics of the id it logged in with.

```yaml
# <data-dir>/mqtt.yaml
users:
  - name: kitchen-sensor              # the device id
    password_hash: "$2a$10$..."       # from `hearth mqtt hash-password`
    allow:
      - topic: hearth/v1/kitchen-sensor/#
        access: readwrite
```

Granting the device its topics is the operator's opt-in. On top of whatever the clients file grants,
the broker enforces:

- Under `hearth/v1/`, a client may publish only to its own topics, `hearth/v1/<its id>/<kind>`, of
  the kinds a device publishes. A grant such as `hearth/#` does not let one device publish as another.
- No client publishes to a `command` topic, not even its own. Only the hub does, after a policy
  decision.
- A client with a device certificate (an enrolled agent) has no protocol id: it cannot publish under
  `hearth/v1/`.
- The [bridge](../mqtt.md#bridge-to-another-broker) to another broker never brings a message in under
  `hearth/v1/`.

A device id becomes a device in the hub's registry with an id derived from it (16 hex digits). An
announce never takes over a device the protocol did not register.

Device certificates for protocol devices are reserved for v1.1.

## Topics

Every topic is `hearth/v1/<id>/<kind>`:

| Kind | Direction | Retain | Device QoS | Purpose |
| --- | --- | --- | --- | --- |
| `announce` | device → hub | SHOULD | 0 or 1 | What the device is: name, entities, commands |
| `state` | device → hub | SHOULD | 0 or 1 | Current values of its entities |
| `telemetry` | device → hub | MUST NOT | 0 or 1 | Numeric readings about the device itself |
| `availability` | device → hub | SHOULD | 0 or 1 | `online` or `offline`; also the device's will |
| `result` | device → hub | MUST NOT | 0 or 1 | The answer to a command |
| `command` | hub → device | never | hub sends at 1 | A command, decided by policy |

QoS 0 is enough: a device that can only publish at QoS 0, such as one using the Arduino PubSubClient
library, is fully supported. The hub publishes commands at QoS 1 and never retains them, so a device
that is not connected never gets a command later. A device SHOULD subscribe to its `command` topic
at QoS 1 if it can, and with a clean session.

The broker keeps messages, retained ones included, in memory only. A device MUST therefore publish
its `announce` (and SHOULD publish its `availability` and `state`) **every time it connects**, not
once.

## Messages

Every message is one UTF-8 JSON object with a version field `"v": 1`. A message:

- MUST be at most **16 KiB**.
- MUST carry `"v": 1`. A message of any other version is refused.
- MAY carry fields this document does not define. Receivers ignore them, so that later v1 revisions
  can add optional fields.

The broker checks each message before it delivers or retains it (and a will when the device
connects, see [availability](#availability)). A message that is malformed, too
large or breaks a rule below is acknowledged and **dropped**: nobody receives it, and the hub logs
the reason (never the payload). Check the hub's log if a device does not appear.

Ids (device, entity, reading) follow the device id rule above. Command names also allow `.` after the
first character, as in `relay.set`. Names, units, descriptions, model strings, string values and
result messages are at most 128 bytes.

### announce

```json
{
  "v": 1,
  "name": "Kitchen sensor",
  "model": "ESP32-DevKitC",
  "manufacturer": "Espressif",
  "sw_version": "1.0.0",
  "entities": [
    {"id": "temperature", "kind": "sensor", "name": "Temperature", "unit": "°C"},
    {"id": "door", "kind": "binary_sensor", "name": "Door"},
    {"id": "relay", "kind": "switch", "name": "Relay"},
    {"id": "chime", "kind": "button", "name": "Chime"}
  ],
  "commands": [
    {"name": "relay.set", "description": "Turn the relay on or off: {\"on\": true}"},
    {"name": "restart"}
  ]
}
```

| Field | | |
| --- | --- | --- |
| `name` | optional | The name shown in Hearth. Default: the device id |
| `model`, `manufacturer`, `sw_version` | optional | Shown with the device |
| `entities` | optional, at most 64 | What the device has. `kind` is `sensor` (a reading), `binary_sensor` (on/off input), `switch` (on/off output) or `button`. `name` and `unit` are optional |
| `commands` | optional, at most 32 | The commands it takes. Hearth sends only commands listed here |

Entity ids and command names are each unique within an announce. A new announce replaces the last:
values of entities it no longer lists are dropped.

### state

The current values of the device's entities, by entity id. Values are booleans, numbers, strings or
`null` (unknown). A message MAY carry only the entities that changed. Values of ids the announce did
not list, and of buttons, are ignored.

```json
{"v": 1, "state": {"temperature": 21.5, "door": false, "relay": true}}
```

### telemetry

Numeric readings about the device itself, such as signal strength or free memory, by id (at most 64,
finite numbers only).

```json
{"v": 1, "values": {"rssi": -61, "heap_free": 182000, "uptime_s": 3600}}
```

The hub keeps the latest state and telemetry values in the device's facts, and writes them at most
every 2 seconds. History is not kept in v1.

### availability

```json
{"v": 1, "status": "online"}
```

`status` is `online` or `offline`. A device SHOULD set its MQTT will to
`{"v":1,"status":"offline"}` on its availability topic, retained, so that other subscribers learn
when it drops off. A will under `hearth/v1/` MUST be exactly that: an `offline` availability message
on the device's own availability topic. The broker sends a will without checking it as a message, so
it checks it at CONNECT, and refuses a connection with any other will there. The hub does not
depend on the will:

- A device is online from its announce while it stays connected. The hub marks it seen every 10
  seconds while its connection lasts.
- It is offline as soon as its last connection ends, or when it publishes `offline` (before a deep
  sleep, say). It is online again with its next announce.

### command

Published by the hub on the device's `command` topic:

```json
{"v": 1, "id": "5f0c1e2d3a4b5c6d7e8f90a1b2c3d4e5", "command": "relay.set", "params": {"on": true}}
```

| Field | |
| --- | --- |
| `id` | A unique id of 16 to 64 lowercase hex digits. The device MUST echo it in its result |
| `command` | One of the names the device announced |
| `params` | Optional. A JSON object of at most 4 KiB, whose meaning the device defines |

### result

The device MUST answer each command it receives, on its `result` topic, within 10 seconds:

```json
{"v": 1, "id": "5f0c1e2d3a4b5c6d7e8f90a1b2c3d4e5", "ok": true, "message": "relay on"}
```

`ok` is whether the command succeeded; `message` is optional. A device SHOULD publish its new
`state` after a command that changes it. A result only answers a command sent to the same device: a
device cannot answer another's. A command with no result in 10 seconds fails as timed out.

## Commands, policy and audit

Sending a command is the policy action **`device.command`**, of class **dangerous**, for a signed-in
admin of the web API (`POST /api/v1/devices/{id}/commands`) who entered the admin password again in
the last 5 minutes (`POST /api/v1/session/reauth`), as for the hub's other dangerous web actions. The hub cannot know what a command does:
a relay may switch a lamp or a heater, and the announce is only the device's word. So every command
is dangerous, whatever the device calls it, and a policy file can hold or deny it like any dangerous
action (see [Guardrails](../guardrails.md)). Automations and MCP clients cannot send commands in v1.

```sh
curl -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"command": "relay.set", "params": {"on": true}}' \
  https://hub.lan:8443/api/v1/devices/<device id>/commands
```

Each decision is in the audit log, with the device and the command's name, and its outcome (`ok`, or
the error and the device's message). The params are not: they may hold anything the device takes.
The hub refuses, before policy, a command the device did not announce or with params that are not
a JSON object; it answers 503 if the device is not connected to this hub.

## Versioning

- The topic carries the major version (`hearth/v1/`) and every message its `"v"`. A breaking change
  makes a v2, with its own topics: a hub may serve both.
- Within v1, new optional fields may be added to messages and new entity kinds or message kinds may
  be defined. Devices and hubs MUST ignore fields they do not know.
- A hub that does not know an entity kind refuses the announce, so a device SHOULD stick to the
  kinds listed here.

## HTTP

An HTTP transport, mirroring each MQTT message with a `POST`, is **reserved for v1.1**. In v1 a
device uses MQTT.

## Limits of v1

- One hub: in a [cluster](../cluster.md) every hub runs its own broker. Point a device at one hub;
  commands go only through the hub it is connected to.
- No history of state or telemetry; the latest value of each is kept.
- No device certificate identity, no HTTP transport (both reserved for v1.1).
