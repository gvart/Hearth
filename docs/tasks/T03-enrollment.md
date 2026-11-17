# T3 — PKI and enrollment

**Branch:** `t3-enrollment` · **Depends on:** T2, T4

## Goal
Agents join a hub with a one-time token and from then on talk over mTLS.

## Scope
- `internal/pki`: on first hub start, create an ECDSA P-256 CA in the data dir (key 0600). Hub server cert
  issued from it, SANs = configured hostnames/IPs + tailnet name later.
- `hearth token create --ttl 15m [--labels k=v]` → prints token + join one-liner. Tokens are random 32 bytes,
  stored **hashed** in `tokens` table, single-use, with expiry.
- Enrollment endpoint (plain TLS, server-auth only, pinned via CA fingerprint embedded in the token string):
  agent sends token + CSR → hub validates, signs a client cert (device_id in CN/URI SAN, 1-year validity),
  marks token used, writes `audit_log`.
- `hearth agent join <hub-url> <token>` stores cert, key, CA in the agent data dir.
- Hub `AgentService` requires client certs from this CA; device_id taken from the cert, never from the payload.
- `hearth device revoke <id>` → revocation list in store; revoked certs are rejected on connect.

## Done when
- Tests: happy path; expired token; reused token; wrong CA fingerprint; revoked cert rejected;
  `Hello` claiming another device_id is ignored in favour of the cert identity.
- No secret ever appears in logs (add a test that greps captured logs for the token).
