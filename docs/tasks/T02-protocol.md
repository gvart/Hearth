# T2 — Agent ↔ hub protocol

**Branch:** `t2-protocol` · **Depends on:** T1 · **Parallel with:** T4

## Goal
A versioned protobuf contract and Connect-RPC service for the agent stream.

## Scope
- `proto/hearth/agent/v1/agent.proto`, generated into `internal/proto` with buf (`buf.yaml`, `buf.gen.yaml`, `task proto`).
- Service `AgentService` with one bidirectional stream `Connect(stream AgentMessage) returns (stream HubMessage)`.
- `AgentMessage` oneof: `Hello` (device_id, hostname, os, arch, kernel, cpu_model, cpu_cores, mem_total,
  disks, interfaces{name, mac, ips}, agent_version, capabilities), `Heartbeat` (ts, uptime),
  `MetricsBatch` (repeated samples: name, labels, value, ts), `ExecResult` (stub).
- `HubMessage` oneof: `Welcome` (server_time, heartbeat_interval), `ExecRequest` (stub), `Ping`.
- Protocol version field in `Hello`; hub rejects unknown major versions with a clear error.
- `buf lint` + `buf breaking` (against main) in CI.

## Out of scope
TLS, enrollment, persistence — use an in-process test server.

## Done when
- A round-trip test: in-memory hub accepts a stream, receives `Hello` + 3 heartbeats, replies `Welcome`.
- Version mismatch test returns `CodeFailedPrecondition`.
- `buf lint` is clean.
