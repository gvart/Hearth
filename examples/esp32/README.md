# ESP32 reference client for the Device Protocol

A small [PlatformIO](https://platformio.org/) project (Arduino framework, PubSubClient, ArduinoJson 7)
that joins Hearth with the [Device Protocol v1](../../docs/spec/device-protocol-v1.md). It:

- connects to the hub's MQTT broker over TLS, as its own MQTT user, with an `offline` will;
- announces a relay (`switch`) and the chip's temperature (`sensor`), and the command `relay.set`;
- publishes their state, and its Wi-Fi signal, free heap and uptime as telemetry, every 30 seconds;
- turns the relay on or off on `relay.set` with `{"on": true}` or `{"on": false}`, and answers each
  command with a result.

**This example is not compiled or run in CI.** It is checked against the spec by reading only; the
hub side of the protocol is tested in Go (`internal/mqtt`, `internal/hub`). If you run it on a board,
please tell us how it went in an issue.

## Use it

1. On the hub, hash a password for the device and give it a user in `<data-dir>/mqtt.yaml`, named by
   its id, with its topics. Then restart the hub with `--mqtt-listen :8883`.

   ```sh
   hearth mqtt hash-password
   ```

   ```yaml
   users:
     - name: kitchen-sensor
       password_hash: "$2a$10$..."
       allow:
         - topic: hearth/v1/kitchen-sensor/#
           access: readwrite
   ```

2. Copy `src/config.example.h` to `src/config.h` and fill it in: Wi-Fi, the hub's name (one its
   certificate carries) and port, the device id and password, the relay's GPIO, and the hub CA from
   `curl http://hub.lan:7080/ca.crt`. `config.h` is ignored by git.

3. Build and flash, and watch the serial log:

   ```sh
   pio run -t upload && pio device monitor
   ```

The device shows up with the other devices in the web UI, under the name it announced. Send it a
command, as a signed-in admin who entered the password again in the last 5 minutes (each one is the
dangerous policy action `device.command`, audited):

```sh
curl -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"command": "relay.set", "params": {"on": true}}' \
  https://hub.lan:8443/api/v1/devices/<device id>/commands
```

If the device does not appear, check the hub's log for `mqtt client refused` (a wrong password or
will topic) or `mqtt device message refused` (a message the protocol does not accept, with the
reason).

## Notes

- PubSubClient publishes at QoS 0 only, which the protocol allows. Its default packet buffer (256
  bytes) is too small for an announce, so the sketch raises it to 1 KiB.
- The broker keeps nothing across a hub restart, so the sketch announces itself on every connect.
