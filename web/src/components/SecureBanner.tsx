import { useState } from 'react';
import type { TlsInfo } from '../api/client.ts';
import { useTlsInfo } from '../api/hooks.ts';

const docsURL = 'https://github.com/gvart/hearth/blob/main/docs/https.md';
const dismissKey = 'hearth.secureBanner.dismissed';

function readDismissed(): boolean {
  try {
    return localStorage.getItem(dismissKey) === '1';
  } catch {
    return false;
  }
}

function saveDismissed() {
  try {
    localStorage.setItem(dismissKey, '1');
  } catch {
    // Storage blocked: the banner just comes back next time.
  }
}

/**
 * The HTTPS address for this page. Browsers check the hub certificate by
 * name, so the current host is kept only if the certificate covers it.
 */
function secureURL(loc: Pick<Location, 'hostname' | 'pathname' | 'search'>, info: TlsInfo) {
  const current = loc.hostname.replace(/^\[|\]$/g, '');
  const covered = info.hosts.some((h) => h.toLowerCase() === current.toLowerCase());
  const host = covered ? current : (info.hosts[0] ?? current);
  const hostPart = host.includes(':') ? `[${host}]` : host;
  return { url: `https://${hostPart}:${info.port}${loc.pathname}${loc.search}`, covered, host };
}

/**
 * Shown on plain HTTP away from localhost (an insecure context), where the
 * browser blocks installing the app, the service worker and the clipboard.
 */
export function SecureBanner() {
  const insecure = !window.isSecureContext;
  const [dismissed, setDismissed] = useState(readDismissed);
  const info = useTlsInfo(insecure && !dismissed);

  if (!insecure || dismissed || !info.data) {
    return null;
  }
  const { url, covered, host } = secureURL(window.location, info.data);

  return (
    <aside className="secure-banner" aria-label="Secure address">
      <div className="secure-banner-body">
        <p>
          <strong>Open the secure address to install the app and enable copy:</strong>{' '}
          <a href={url}>{url.replace(/\/$/, '')}</a>
        </p>
        <p className="small muted">
          First time on this device? <a href="/ca.crt">Download the hub CA</a> and trust it once (
          <a href={docsURL} target="_blank" rel="noreferrer">
            how
          </a>
          ). Check its SHA-256 fingerprint:
        </p>
        <code className="secure-banner-fp">{info.data.ca_fingerprint}</code>
        {covered ? null : (
          <p className="small muted">
            The hub certificate does not cover this address, so the link uses {host}. Start the hub with{' '}
            <code>--host {window.location.hostname.replace(/^\[|\]$/g, '')}</code> to use this one.
          </p>
        )}
      </div>
      <button
        className="btn btn-ghost icon-btn"
        type="button"
        aria-label="Dismiss"
        onClick={() => {
          saveDismissed();
          setDismissed(true);
        }}
      >
        ✕
      </button>
    </aside>
  );
}
