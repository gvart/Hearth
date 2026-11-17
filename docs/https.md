# HTTPS for the web UI

Browsers treat `http://nas.lan:7080` as an insecure context: the Hearth app can't be installed,
its service worker doesn't run, and the "Copy" buttons fall back to select + Ctrl/⌘+C. Only
`http://localhost` is exempt.

The hub therefore also serves the UI and API over HTTPS on its agent port, with a certificate from
its own certificate authority (CA):

| Address                      | What                                                         |
| ---------------------------- | ------------------------------------------------------------ |
| `https://<host>:7443/`       | Web UI and API over HTTPS (and the agent services, as before) |
| `http://<host>:7080/`        | Web UI and API over plain HTTP                               |
| `http://<host>:7080/ca.crt`  | The hub CA certificate (PEM; `?format=der` for DER)          |
| `http://<host>:7080/install.sh`, `/download/*` | Agent installer, HTTP only            |

No certificate is bought or requested from anywhere: each device you browse from trusts the hub CA
**once**, and from then on `https://<host>:7443` is a normal secure site. The CA can only issue
certificates from the hub's data dir; its private key never leaves it, and `/ca.crt` serves only the
certificate.

The installer stays on plain HTTP: `curl` on a new device doesn't trust the hub CA yet. The
"Add device" dialog always gives an `http://<host>:7080/install.sh` command, even when opened over
HTTPS; the agent then pins the hub CA by the fingerprint in its enrollment token.

## 1. Pick the names you browse with

The hub certificate is valid only for the names given with `--host` (default: this machine's
hostname, `localhost`, `127.0.0.1`, `::1`). The browser checks the name in the address bar against
it, so start the hub with every name and IP you use to reach it:

```sh
hearth hub --host nas.lan --host 192.168.1.10
```

In the container image the default hostname is the container's, so always pass them there:
`docker run … ghcr.io/gvart/hearth:<tag> hub --host nas.lan --host 192.168.1.10`.

The first `--host` is the preferred name: when the UI is opened over HTTP at an address the
certificate doesn't cover, its "open the secure address" banner links to that first name. A new
certificate is issued at every start, so changing `--host` only needs a restart; devices that
already trust the CA need nothing.

## 2. Get the CA certificate and check its fingerprint

Open `http://<host>:7080/` in the browser; the banner at the top links to the CA
(`http://<host>:7080/ca.crt`) and shows its SHA-256 fingerprint. Or download it directly:

```sh
curl -fsSLo ca.crt http://nas.lan:7080/ca.crt
openssl x509 -noout -fingerprint -sha256 -in ca.crt
```

Compare the fingerprint with the one the hub logs at startup (`ca_fingerprint` in the
`hub listening` line, lower-case hex without colons) or with the hub's own copy:

```sh
openssl x509 -noout -fingerprint -sha256 -in <data-dir>/ca.crt   # on the hub (/var/lib/hearth in the container)
```

Trusting a CA lets it vouch for **any** site on that device, so only trust a certificate whose
fingerprint matches. Hearth's CA is limited in practice to what the hub issues, but your OS doesn't
know that.

## 3. Trust it once per device

### macOS

1. Double-click the downloaded `ca.crt`; Keychain Access adds it to the **login** keychain.
2. Open it there ("Hearth CA"), expand **Trust**, set **When using this certificate** to
   **Always Trust**, close the window and confirm with your password.

Or in a terminal (system-wide, needs admin):

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt
```

Safari and Chrome use the keychain. If Firefox still warns, import the CA there too (see
[Firefox](#firefox-any-os)).

### Windows

1. Download `http://<host>:7080/ca.crt` (or `ca.crt?format=der` for the binary DER form) and
   double-click it.
2. **Install Certificate…** → **Current User** → **Place all certificates in the following store** →
   **Browse…** → **Trusted Root Certification Authorities** → Finish, and accept the warning.

Or run `certmgr.msc`, right-click **Trusted Root Certification Authorities → Certificates** →
**All Tasks → Import…**, or in a terminal: `certutil -user -addstore Root ca.crt`.
Edge and Chrome use this store.

### Linux

System store (curl, most CLI tools; Debian/Ubuntu shown):

```sh
sudo cp ca.crt /usr/local/share/ca-certificates/hearth-ca.crt
sudo update-ca-certificates
```

On Fedora/RHEL: `sudo cp ca.crt /etc/pki/ca-trust/source/anchors/hearth-ca.crt && sudo update-ca-trust`.

Chrome and Chromium on Linux use their own NSS database instead. With `certutil` from `libnss3-tools`
(Debian/Ubuntu) or `nss-tools` (Fedora):

```sh
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Hearth CA" -i ca.crt
```

Or in Chrome: **Settings → Privacy and security → Security → Manage certificates → Authorities →
Import**, and tick "Trust this certificate for identifying websites". Restart the browser afterwards.

### iOS and iPadOS

1. In Safari, open `http://<host>:7080/ca.crt` and allow the download of the configuration profile.
2. **Settings → General → VPN & Device Management** → the "Hearth CA" profile → **Install**.
3. **Settings → General → About → Certificate Trust Settings** → turn on full trust for
   **Hearth CA**.

Step 3 is easy to miss: without it the profile is installed but Safari still rejects the hub.

### Android

1. Download `http://<host>:7080/ca.crt`.
2. **Settings → Security & privacy → More security settings → Encryption & credentials →
   Install a certificate → CA certificate** (the path varies by vendor; search Settings for
   "CA certificate"), confirm the warning and pick the file.

Chrome on Android trusts user-installed CAs. Many other apps don't (apps opt in), which doesn't
matter for the Hearth UI.

### Firefox (any OS)

**Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import…**, pick
`ca.crt` and tick "Trust this CA to identify websites".

## 4. Open the secure address

Browse to `https://<host>:7443/` with one of the `--host` names. Log in again: the HTTPS and HTTP
addresses keep separate sessions (cookies are per host, and the HTTPS one is `Secure`), so a login
on one doesn't carry over to the other. Over HTTPS you can install the app ("Install Hearth" in the
browser menu, or **Share → Add to Home Screen** on iOS) and the Copy buttons work.

## Troubleshooting

- **"Your connection is not private" / `NET::ERR_CERT_AUTHORITY_INVALID`**: the CA isn't trusted in
  the store this browser uses (see Firefox and Linux Chrome above), or on iOS full trust is off.
- **`NET::ERR_CERT_COMMON_NAME_INVALID`**: the address isn't one of the `--host` names. Use one that
  is, or restart the hub with that name added.
- **The banner keeps showing on `http://…`**: it's shown on every plain-HTTP address except
  localhost. Use the HTTPS link, or dismiss it with ✕.
- **Behind your own TLS reverse proxy**: point the proxy at `http://<hub>:7080` and use the proxy's
  certificate; none of the above is needed.
- **Starting over**: the CA lives in the hub data dir (`ca.crt`, `ca.key`). Deleting them creates a
  new CA on the next start, which every device must trust again and every agent must re-enroll with.
