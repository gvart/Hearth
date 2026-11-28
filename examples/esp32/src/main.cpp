// SPDX-License-Identifier: AGPL-3.0-only
//
// Reference client of the Hearth Device Protocol v1 (docs/spec/device-protocol-v1.md) for the
// ESP32, with the Arduino framework, PubSubClient and ArduinoJson 7. It joins Wi-Fi, connects to
// the hub's MQTT broker over TLS as its own MQTT user, announces a relay and a reading, publishes
// their state and some telemetry, and takes one command, relay.set.
//
// Fill in config.h (copy config.example.h) before you build. Not built in CI.

#include <Arduino.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>

#include "config.h"

// The device's topics: hearth/v1/<id>/<kind>, with the id of its MQTT user.
static const String base = String("hearth/v1/") + HEARTH_DEVICE_ID + "/";
static const String tAnnounce = base + "announce";
static const String tState = base + "state";
static const String tTelemetry = base + "telemetry";
static const String tAvailability = base + "availability";
static const String tCommand = base + "command";
static const String tResult = base + "result";

static const char kOffline[] = "{\"v\":1,\"status\":\"offline\"}";
static const char kOnline[] = "{\"v\":1,\"status\":\"online\"}";

static WiFiClientSecure net;
static PubSubClient mqtt(net);
static bool relayOn = false;
static unsigned long lastTelemetry = 0;

// publishJSON serializes doc and publishes it; retained for announce, state and availability.
static void publishJSON(const String &topic, JsonDocument &doc, bool retained) {
  char buf[1024];
  size_t n = serializeJson(doc, buf, sizeof(buf));
  mqtt.publish(topic.c_str(), reinterpret_cast<const uint8_t *>(buf), n, retained);
}

static void announce() {
  JsonDocument doc;
  doc["v"] = 1;
  doc["name"] = HEARTH_DEVICE_NAME;
  doc["model"] = "ESP32-DevKitC";
  doc["manufacturer"] = "Espressif";
  doc["sw_version"] = "1.0.0";
  JsonArray entities = doc["entities"].to<JsonArray>();
  JsonObject relay = entities.add<JsonObject>();
  relay["id"] = "relay";
  relay["kind"] = "switch";
  relay["name"] = "Relay";
  JsonObject temp = entities.add<JsonObject>();
  temp["id"] = "chip_temperature";
  temp["kind"] = "sensor";
  temp["name"] = "Chip temperature";
  temp["unit"] = "°C";
  JsonObject cmd = doc["commands"].to<JsonArray>().add<JsonObject>();
  cmd["name"] = "relay.set";
  cmd["description"] = "Turn the relay on or off: {\"on\": true}";
  publishJSON(tAnnounce, doc, true);
}

static void publishState() {
  JsonDocument doc;
  doc["v"] = 1;
  doc["state"]["relay"] = relayOn;
  doc["state"]["chip_temperature"] = temperatureRead();
  publishJSON(tState, doc, true);
}

static void publishTelemetry() {
  JsonDocument doc;
  doc["v"] = 1;
  doc["values"]["rssi"] = WiFi.RSSI();
  doc["values"]["heap_free"] = ESP.getFreeHeap();
  doc["values"]["uptime_s"] = millis() / 1000;
  publishJSON(tTelemetry, doc, false);
}

static void publishResult(const char *id, bool ok, const char *message) {
  JsonDocument doc;
  doc["v"] = 1;
  doc["id"] = id;
  doc["ok"] = ok;
  doc["message"] = message;
  publishJSON(tResult, doc, false);
}

// onMessage handles a command from the hub. Every command gets a result, with its id.
static void onMessage(char *topic, byte *payload, unsigned int length) {
  if (tCommand != topic) {
    return;
  }
  JsonDocument cmd;
  if (deserializeJson(cmd, payload, length) != DeserializationError::Ok || cmd["v"] != 1) {
    return;  // not a v1 command: there is no id to answer
  }
  const char *id = cmd["id"] | "";
  const char *name = cmd["command"] | "";
  if (strcmp(name, "relay.set") != 0) {
    publishResult(id, false, "unknown command");
    return;
  }
  JsonVariant on = cmd["params"]["on"];
  if (!on.is<bool>()) {
    publishResult(id, false, "params must be {\"on\": true} or {\"on\": false}");
    return;
  }
  relayOn = on.as<bool>();
  digitalWrite(HEARTH_RELAY_PIN, relayOn ? HIGH : LOW);
  publishResult(id, true, relayOn ? "relay on" : "relay off");
  publishState();
}

static void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
}

// connectMQTT logs in as the device's own user, with an offline will on its availability topic,
// then subscribes to its commands and announces itself: on every connect, as the broker keeps
// nothing across a hub restart.
static void connectMQTT() {
  while (!mqtt.connected()) {
    if (mqtt.connect(HEARTH_DEVICE_ID, HEARTH_DEVICE_ID, HEARTH_MQTT_PASSWORD, tAvailability.c_str(), 0,
                     true, kOffline)) {
      mqtt.subscribe(tCommand.c_str(), 1);
      mqtt.publish(tAvailability.c_str(), kOnline, true);
      announce();
      publishState();
      publishTelemetry();
    } else {
      Serial.printf("MQTT connect failed, state %d; retrying\n", mqtt.state());
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(HEARTH_RELAY_PIN, OUTPUT);
  digitalWrite(HEARTH_RELAY_PIN, LOW);
  connectWiFi();
  // The hub's certificate is checked against the hub CA (http://<hub>:7080/ca.crt).
  net.setCACert(HEARTH_CA_PEM);
  mqtt.setServer(HEARTH_HOST, HEARTH_PORT);
  // PubSubClient's default packet buffer is 256 bytes: too small for an announce.
  mqtt.setBufferSize(1024);
  mqtt.setCallback(onMessage);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }
  if (!mqtt.connected()) {
    connectMQTT();
  }
  mqtt.loop();
  if (millis() - lastTelemetry > 30000) {
    lastTelemetry = millis();
    publishTelemetry();
    publishState();
  }
}
