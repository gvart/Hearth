// SPDX-License-Identifier: AGPL-3.0-only

//! An example Hearth WASM plugin in Rust: a virtual lamp that can be turned
//! on and off. It speaks protocol version 1 (see docs/plugins.md) on stdin
//! and stdout, one message per line, and handles one message at a time.
//!
//! Build it for WASI preview 1 and point the hub at its manifest:
//!
//! ```sh
//! rustup target add wasm32-wasip1
//! cargo build --release --target wasm32-wasip1
//! cp target/wasm32-wasip1/release/rust-lamp.wasm lamp.wasm
//! hearth hub --plugin ./plugin.yaml
//! ```

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    let mut on = false;
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("not JSON: {e}");
                continue;
            }
        };
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let reply = match msg["type"].as_str().unwrap_or("") {
            "hello" => json!({"type": "hello", "protocol": 1, "name": "rust-lamp", "version": "0.1.0"}),
            "ping" => json!({"type": "pong", "id": id}),
            "discover" => json!({"type": "devices", "id": id, "devices": [{
                "id": "lamp", "name": "Lamp", "kind": "light",
                "entities": [{"id": "on", "name": "On", "kind": "switch", "state": on}],
            }]}),
            "command" => match msg["command"].as_str().unwrap_or("") {
                c @ ("turn_on" | "turn_off") => {
                    on = c == "turn_on";
                    let state = json!({"type": "state", "device": "lamp", "entity": "on", "state": on});
                    writeln!(out, "{state}")?;
                    let output = if on { "lamp is on" } else { "lamp is off" };
                    json!({"type": "result", "id": id, "ok": true, "output": output})
                }
                c => json!({"type": "result", "id": id, "ok": false, "error": format!("unknown command {c}")}),
            },
            // Newer hubs may send more: ignore what is not known.
            _ => continue,
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
    Ok(())
}
