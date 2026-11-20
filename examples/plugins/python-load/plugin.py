# SPDX-License-Identifier: AGPL-3.0-only
"""Example Hearth exec plugin in Python: the hub host's load average.

It speaks protocol version 1 (see docs/plugins.md) with the standard library
only: it reports one device with three entities, pushes their state every
LOAD_INTERVAL seconds, and offers a read-class "refresh" command.
"""

import json
import os
import sys
import threading

NAME = os.environ.get("HEARTH_PLUGIN", "python-load")
INTERVAL = float(os.environ.get("LOAD_INTERVAL", "10"))
ENTITIES = [("load1", "Load (1 min)"), ("load5", "Load (5 min)"), ("load15", "Load (15 min)")]

_out = threading.Lock()


def send(msg):
    # One JSON object per line, flushed at once: the hub reads lines.
    with _out:
        sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def loads():
    return dict(zip((e for e, _ in ENTITIES), os.getloadavg()))


def push_state():
    for entity, value in loads().items():
        send({"type": "state", "device": "host", "entity": entity, "state": round(value, 2)})


def pusher(stop):
    while not stop.wait(INTERVAL):
        push_state()


def handle(msg):
    kind = msg.get("type")
    if kind == "hello":
        if msg.get("protocol") != 1:
            sys.exit("hub speaks protocol %r, this plugin 1" % msg.get("protocol"))
        send({"type": "hello", "protocol": 1, "name": NAME, "version": "0.1.0"})
    elif kind == "ping":
        send({"type": "pong", "id": msg["id"]})
    elif kind == "discover":
        values = loads()
        send({"type": "devices", "id": msg["id"], "devices": [{
            "id": "host", "name": "Hub host", "kind": "host",
            "entities": [{"id": e, "name": n, "kind": "sensor", "state": round(values[e], 2)} for e, n in ENTITIES],
        }]})
    elif kind == "command":
        if msg.get("command") == "refresh":
            push_state()
            send({"type": "result", "id": msg["id"], "ok": True, "output": "refreshed"})
        else:
            send({"type": "result", "id": msg["id"], "ok": False, "error": "unknown command"})
    # Unknown message types are ignored: newer hubs may send more.


def main():
    stop = threading.Event()
    threading.Thread(target=pusher, args=(stop,), daemon=True).start()
    for line in sys.stdin:
        if line.strip():
            handle(json.loads(line))
    stop.set()


if __name__ == "__main__":
    main()
