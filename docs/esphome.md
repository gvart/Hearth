---
title: ESPHome
description: Adopt ESPHome devices through their native API, see their sensors, binary sensors and switches live, and turn switches or press buttons through policy.
---

Hearth adopts the ESPHome devices you already run through their native API, the one Home Assistant
uses, on TCP port 6053. Nothing is flashed or installed: the device keeps its firmware and its YAML,
and Home Assistant can stay connected alongside Hearth. Hearth reads its sensors, binary sensors,
switches, buttons and text sensors, keeps their states live, and writes only when you turn a switch
or press a button on a device you adopted with calls allowed.

> **Not yet tested on a real device.** This integration has been tested against a fake ESPHome device
> written from ESPHome's own frame helpers and `api.proto`. It has not been run against real firmware
> yet.

## Find the device

ESPHome devices with the native API announce `_esphomelib._tcp` over mDNS. A network scan (see
[Network discovery](discovery.md)) lists them under **On your network** as smart-home devices, with an
**Adopt ESPHome** action that opens the dialog below with the device's name and IP filled in.

You can also adopt a device by hand: **Platforms → Connect platform → ESPHome device**.

## Adopt it

Hearth needs:

| Field             | What to give                                                                           |
| ----------------- | -------------------------------------------------------------------------------------- |
| Name              | How Hearth names the device. Unique on the hub.                                        |
| IP address        | The device's IP, with `:port` if it is not 6053. Host names, `.local` too, are refused. |
| API encryption key| `api: encryption: key:` from the device's YAML: base64 of 32 bytes.                    |
| Allow calls       | Off by default: Hearth only reads the device. See [Calls](#calls).                     |

```yaml
# The device's YAML
api:
  encryption:
    key: "px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA="
```

A device without `encryption:` speaks plaintext: choose **Not encrypted** and leave the key empty.
Firmware older than ESPHome 2026.1 may also have an API `password:`; give it there. Prefer a key: on
plaintext the states, and the password, cross the network in the clear.

The key and the password are sealed (AES-256-GCM, under a key of their own derived from the hub CA
key) before they reach the database, and are re-sealed when the hub CA is rotated. They are never
logged, served by the API or written to the audit log, and never shown again: to change one, remove
the device and adopt it again.

Give the device a fixed address (a DHCP reservation): Hearth connects to the IP it was given. A device
that moves shows as unavailable until you adopt it again at its new address.

## What Hearth shows

The device's page (**Platforms → the device**) lists every entity the device does not disable by
default, with its state:

| Entity        | State                                                   |
| ------------- | ------------------------------------------------------- |
| Sensor        | Its value and unit, with the decimals the device shows  |
| Binary sensor | On or off, or Detected, Open, … by its device class     |
| Switch        | On or off                                               |
| Text sensor   | Its text                                                |
| Button        | None: it can only be pressed                            |

Hearth subscribes to the device's states, so a change on the device reaches the hub at once; the page
reads them from the hub every 2 seconds. The page also shows what the device says of itself: its
ESPHome version, board, MAC and friendly name.

Every master of a hub cluster connects to every device itself: with three masters, a device has three
Hearth connections, as well as Home Assistant's. An ESPHome device takes a handful of API clients at
once; if yours refuses more, adopt it on a smaller cluster. A device that cannot be reached, or
rejects the key, shows as unavailable with the reason, and Hearth keeps trying: every few seconds at
first, once a minute after a rejected key.

## Calls

A device adopted with **Allow switch and button calls** offers **Turn on**, **Turn off** and **Press**
beside its switches and buttons. Each one is a policy action, decided and audited before anything is
sent to the device:

| Call                | Action         | Class | Sends                       |
| ------------------- | -------------- | ----- | --------------------------- |
| Turn a switch on/off| `esphome.call` | safe  | `SwitchCommandRequest`      |
| Press a button      | `esphome.call` | safe  | `ButtonCommandRequest`      |

A device adopted read-only refuses every call, and the refusal is audited as a denial. Only a
signed-in admin in the web UI may call; automations and MCP clients may not, yet. Adopting
(`esphome.device.add`) and removing (`esphome.device.remove`) a device are policy actions too, both
safe and audited; the audit entry names the address and the encryption mode, never the key.

Hearth sends nothing else: no firmware updates, no YAML, no logs, no Home Assistant services.

## API

| Method and path                            | What it does                                               |
| ------------------------------------------ | ---------------------------------------------------------- |
| `GET /api/v1/esphome/devices`              | The adopted devices and their connection state             |
| `POST /api/v1/esphome/devices`             | Adopts one: `{"name", "address", "key", "password", "control"}` |
| `GET /api/v1/esphome/devices/{id}`         | The device and its entities with their states              |
| `DELETE /api/v1/esphome/devices/{id}`      | Forgets the device and its key                             |
| `POST /api/v1/esphome/devices/{id}/call`   | `{"key": 3, "action": "on"}`: `on`, `off` or `press`       |

Every route needs the admin session.

## Protocol notes

Hearth speaks the native API itself, in pure Go: frames of `0x00`, a varint length and a varint
message type for plaintext, or `0x01` and a 16-bit length for Noise
(`Noise_NNpsk0_25519_ChaChaPoly_SHA256` with the encryption key as the pre-shared key, using
[flynn/noise](https://github.com/flynn/noise)). The messages it uses are a subset of ESPHome's
`api.proto`, which is MIT licensed, vendored under `proto/hearth/esphome/v1`. Hearth answers the
device's pings and pings it in turn, so a device that lost power is noticed within a minute.
