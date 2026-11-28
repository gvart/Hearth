---
title: Enrollment link v1
description: The hearth://enroll link in the Add device dialog's QR code - what it holds and how an app enrolls a device with it.
---

<!-- SPDX-License-Identifier: CC-BY-4.0 -->

The "Add device" dialog can show its enrollment token as a QR code, so an app on a phone (an old
Android phone as a node, #79) enrolls by scanning it instead of typing a command. The QR code holds
one `hearth://enroll` link. This document specifies that link. It is licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), so you can implement it in any app under
any licence.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## The link

```text
hearth://enroll?ca=<fingerprint>&hub=<hub URL>&token=<token>&v=1
```

A URI (RFC 3986) with scheme `hearth`, host `enroll`, no path, and a query of
`application/x-www-form-urlencoded` parameters. The hub writes them in this order; an app MUST NOT
depend on the order and MUST ignore parameters it does not know.

| Parameter | Value                                                                                         |
| --------- | --------------------------------------------------------------------------------------------- |
| `v`       | `1`, this version. An app MUST refuse a link with another `v`.                                |
| `hub`     | The hub's agent URL, percent-encoded: `https://<host>:7443`, an IPv6 host in brackets.        |
| `ca`      | SHA-256 of the hub CA certificate (its DER bytes), 64 lowercase hex digits.                   |
| `token`   | The single-use enrollment token, `hearth2.<secret>.<ca>.<hub>`, as the install command has it. |

For example (wrapped here):

```text
hearth://enroll?ca=3f1c…9a07&hub=https%3A%2F%2F192.168.1.10%3A7443
  &token=hearth2.ShLy…bxrY.kEl4…ubY.aHR0cHM6Ly8xOTIuMTY4LjEuMTA6NzQ0Mw&v=1
```

## The token

The token is the authority; `hub` and `ca` repeat what it holds so an app can show where it is about
to enroll before it parses the token. The token is four dot-separated fields, the last three
base64url without padding (RFC 4648 §5):

1. `hearth2`
2. the secret, 32 random bytes
3. the SHA-256 fingerprint of the hub CA certificate, 32 bytes
4. the hub's agent URL, UTF-8, at most 512 bytes

An app MUST decode the token and refuse the link when the token's fingerprint is not `ca` or its URL
is not `hub`.

## Enrolling

An app enrolls exactly as `hearth agent join` does: it connects to `hub` over TLS, accepts the hub's
certificate only if it chains to a CA certificate whose SHA-256 is `ca` (the fingerprint pins the
CA; the system trust store plays no part), and sends the token with its certificate signing request.
The hub accepts a token once, until it expires (15 minutes by default, at most 24 hours), and audits
the enrollment.

## Handling the link

The link holds a secret: anyone who has it before the device enrolls can enroll a device of their
own in its place. So:

- An app MUST NOT log the link or the token, nor keep either after enrolling.
- An app SHOULD enroll at once after the scan, so the token is spent before anyone else can use it.
- The hub's web UI draws the QR code only when you click **Show QR**, and removes it once a device
  joined with the token or the token expired. Revoke a token you showed by mistake under **Unused
  enrollment tokens** on the **Devices** page, or with `hearth token revoke <id>`.
