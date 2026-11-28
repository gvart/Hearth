# Hosted relay and push notifications

**Status:** proposal, not decided. Issue: [#72](https://github.com/gvart/hearth/issues/72). Related:
[#48](https://github.com/gvart/hearth/issues/48) (built-in Tailscale), [#79](https://github.com/gvart/hearth/issues/79)
(Android agent app).

## Problem

Away from home, an admin wants two things from a phone: open the web UI (to approve a held action,
restart something, read a log), and get a notification when the hub needs them. Today that takes a
VPN, Tailscale, or a port forward plus a reverse proxy, and push goes through ntfy, Telegram or a
webhook that the owner sets up. A relay run by the project (or by the owner) would make both work with
no network setup.

## Goals

- Reach the web UI and API of a hub from the internet with no inbound port, no VPN and no DNS setup.
- Push notifications to a phone, including approval requests, with no third-party account.
- **The relay never sees plaintext.** It never holds a key that decrypts traffic: no password, session
  cookie, terminal byte or notification body.
- Opt-in, off by default. A hub without the relay keeps working exactly as today (local-first).
- The relay is one more way in, not a replacement: Tailscale, a reverse proxy and ntfy stay supported
  (adopt, don't replace).
- Every request through the relay is an ordinary API request: same sign-in, same policy, same audit.

## Non-goals

- Agents through the relay. Agents keep dialling a hub over mTLS on the LAN (or a tailnet).
- Hub-to-hub cluster traffic through the relay.
- Any processing on the relay beyond routing bytes and forwarding pushes.

## Remote access: options

All options start the same way: the hub dials out to the relay and keeps one long-lived connection
open (as agents dial out to the hub), so nothing on the LAN is opened. The relay assigns the hub a
name such as `<hub-id>.relay.example`. A browser connects to that name, and the relay forwards its
bytes over the hub's connection. The options differ in who terminates the browser's TLS.

### A. The relay terminates TLS

The relay holds a public certificate for the name, decrypts, and forwards HTTP to the hub.
Simplest for the browser, but the relay sees the admin password, the session cookie and terminal
traffic. **Rejected**: it breaks the main goal.

### B. TLS passthrough, publicly trusted certificate on the hub (proposed)

The relay routes each connection by its TLS SNI and forwards the raw TLS bytes. The hub terminates TLS
with a certificate for `<hub-id>.relay.example` from a public ACME CA (Let's Encrypt). The hub keeps the
private key in its data dir. Since the relay controls DNS for its zone, issuance uses DNS-01: the hub
asks the relay to publish the challenge TXT record.

- The browser sees normal HTTPS: no CA to install. The PWA and its service worker work, and the
  terminal's rule (TLS reached the hub, `Origin` host matches) holds unchanged.
- The relay sees only metadata: the name, client IPs, timing and sizes.
- Risk: the relay operator controls the DNS zone, so it could get a certificate for the same name
  itself and read the traffic. A CAA record cannot stop that: the relay runs the zone and can rewrite
  it. What is left is detection and choice: the hub watching Certificate Transparency logs for its name
  and alerting on any certificate it did not request, option C below, or a self-hosted relay for owners
  who do not want to trust ours.

### C. TLS passthrough, hub CA certificate

As B, but the hub serves a certificate from its own CA for the relay name. The relay cannot mint one.
The phone must trust the hub CA, as HTTPS on the LAN already requires ([HTTPS](../https.md)). Strongest
against the relay, worst first-run experience. Could be offered next to B as a stricter setting.

### D. Application-level end-to-end encryption

The PWA, served by the relay, encrypts to a key paired over a QR code. Rejected for the browser: whoever
serves the JavaScript can serve a version that leaks the key, so the relay would be trusted anyway.
Only worth it for a native app whose code does not come from the relay.

## Push notifications: options

1. **ntfy, as today.** Works now with a self-hosted server or an access-token protected topic. The
   relay adds nothing here. Document it as the default.
2. **Web Push to the PWA (proposed first step).** The hub sends Web Push messages (RFC 8030, VAPID
   RFC 8292) to the browser's push service (Google, Mozilla, Apple). The payload is encrypted by the
   hub to the subscription's key (RFC 8291), so the push service sees only ciphertext and metadata.
   It needs **no relay**: the hub calls the push service directly. It needs the PWA installed from a
   secure context (the service worker registers only there, `web/src/main.tsx`), and on iOS an
   installed home-screen app. It could ship free, independent of the relay.
3. **APNs and FCM for a native app.** A native app (#79) receives pushes only through credentials the
   app's publisher holds, so a central service must forward them. The hub would encrypt the body
   end to end to the app's key and send it to the relay, which only forwards it to APNs or FCM. This is
   the part of push that needs a hosted service.

Whatever the transport, a pushed approval request follows the existing rules
([guardrails](../guardrails.md#approve-from-your-phone)): the link can only deny, once, and approving
takes a sign-in and the admin password again.

## Hub connector

- A new policy action to turn the relay on or off and change its settings, class `dangerous`: it
  exposes the hub to the internet. From the CLI on the hub host, and from **Settings** in the web UI
  with the admin password again (web UI and CLI parity). Audited, refusals too.
- The relay account credential is sealed in the store like other integration credentials, never logged,
  served or audited. The ACME key and certificate stay in the data dir.
- The connection is TLS to the relay, verified against system roots, with reconnect and backoff. A
  relay that is down never stops the hub.
- The hub's status page shows whether the relay is connected and its public name.
- Through the relay, only the web UI and API are served: not the agent installer or enrollment, not
  the cluster port. Whether `/mcp` goes through is an open question.

## Fit with deny by default, policy and audit

- Turning the relay on is a decision and an audit entry. Requests arriving through it are decided and
  audited like any other, by the master that serves them.
- The internet is a harsher place than the LAN for the one admin password. Login limits are per client
  address, and through the relay every connection arrives from the tunnel: the relay would pass the
  client's address (a PROXY-protocol header inside the tunnel), which is the relay's word, so the hub
  should also limit logins per tunnel. A second factor before the relay ships is an open question.
- Audit entries for requests that came through the relay should say so.

## Cluster

Every master serves the UI, so each master could open its own connection. Approval links open only on
the master that owns the approval, and a link to another master answers `409 not_owner`. Options: one
name per master (`<node>.<hub-id>.relay.example`), or the relay routing to any live master and the UI
redirecting to the owner's name. Each master needs its own certificate (B) or one shared name with the
key on every master. Open question.

## Threat model

| Attacker | Can | Mitigation |
| --- | --- | --- |
| Relay operator, honest but curious | see names, client IPs, timing, sizes | passthrough (B or C): no plaintext |
| Relay operator, malicious | issue a certificate for the hub's name through its DNS (B) | detection only, through CT monitoring; option C or self-hosting to prevent it |
| Relay operator | drop or delay traffic and pushes | none beyond the LAN and other access paths still working |
| Stolen relay credential | register a tunnel for the hub's name and receive its traffic | browsers fail TLS without the hub's key; DNS-01 requests must not be possible with this credential alone (open) |
| Internet attacker | guess the admin password, probe the API | login limits per address and per tunnel, re-auth for sensitive actions, open question on a second factor |
| Push service | see that a push was sent, and when | Web Push and app payloads encrypted end to end |
| Lost phone | a push subscription and maybe a session | push subscriptions revocable from the UI (to build); sessions already expire after 7 days |

## Open questions for the maintainer

- **Pricing and business model**: free tier or not, price, bandwidth and connection caps, what is
  paid (remote access, native push, or both).
- **Who runs it**, where, under what jurisdiction, and what metadata is kept and for how long.
- **Is the relay server open source** and self-hostable, and under which license.
- **Order of work**: built-in Tailscale (#48) and Web Push may cover most needs at no running cost.
  Should they ship first?
- **A second factor** (TOTP, passkeys) before the UI is reachable from the internet.
- **TLS model**: B only, or B and C.
- **Cluster naming**: one name per master or one shared name.
- **MCP over the relay**: allowed, or LAN and tailnet only.
- **Domain** for hub names.
