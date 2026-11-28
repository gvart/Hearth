// SPDX-License-Identifier: AGPL-3.0-only
//
// Copy this file to config.h and fill it in. config.h holds the Wi-Fi and MQTT passwords: it is
// in .gitignore, do not commit it.

#pragma once

#define WIFI_SSID "my-wifi"
#define WIFI_PASSWORD "..."

// The hub: a name its certificate carries (its --host names), and its --mqtt-listen port.
#define HEARTH_HOST "hub.lan"
#define HEARTH_PORT 8883

// The device's MQTT user in the hub's mqtt.yaml: its name is the device id.
#define HEARTH_DEVICE_ID "kitchen-sensor"
#define HEARTH_DEVICE_NAME "Kitchen sensor"
#define HEARTH_MQTT_PASSWORD "..."

// The GPIO the relay is on.
#define HEARTH_RELAY_PIN 2

// The hub CA, from `curl http://hub.lan:7080/ca.crt`.
static const char HEARTH_CA_PEM[] = R"PEM(
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
)PEM";
