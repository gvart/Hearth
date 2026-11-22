import { useEffect, useRef, useState } from 'react';
import type { Device, NetworkHost } from '../api/client.ts';
import { useCreateToken } from '../api/hooks.ts';
import { suggestedName } from '../devices.ts';
import { displayName } from '../format.ts';
import { Modal } from './Modal.tsx';
import { QrCode } from './QrCode.tsx';
import './SettingsPage.css';

const ttls = [
  { value: '15m', label: '15 minutes' },
  { value: '1h', label: '1 hour' },
  { value: '6h', label: '6 hours' },
  { value: '24h', label: '24 hours' },
];

interface Label {
  key: string;
  value: string;
}

/** The labels to send: rows with a key, trimmed. */
function labelsOf(rows: Label[]): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const r of rows) {
    if (r.key.trim() !== '') {
      out[r.key.trim()] = r.value.trim();
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

interface Props {
  /** The discovered host the device is added for, if any: the dialog is prefilled for it. */
  host?: NetworkHost;
  /** The first device that appeared since the dialog opened, if any. */
  joined: Device | undefined;
  onClose: () => void;
  onShow: (d: Device) => void;
}

export function AddDeviceDialog({ host, joined, onClose, onShow }: Props) {
  const create = useCreateToken();
  const { mutate } = create;
  const [name, setName] = useState(() => (host ? suggestedName(host) : ''));
  // On by default: a capable device then becomes a hub, so the laptop that
  // started the first hub can go away. It asks for the password again.
  const [hub, setHub] = useState(true);
  // Guards against StrictMode's double effect minting two tokens.
  const requested = useRef(false);
  useEffect(() => {
    if (!requested.current) {
      requested.current = true;
      mutate(name === '' ? { hub } : { name, hub });
    }
  }, [mutate, name, hub]);

  const tok = create.data;
  /** The name the shown token gives, which edits to the field change only on a new token. */
  const tokenName = create.variables?.name;
  const tokenHub = create.variables?.hub === true;
  const [ttl, setTtl] = useState('15m');
  const [labels, setLabels] = useState<Label[]>([]);
  // Stays open across the new token, which remounts it.
  // Open for a discovered host, so its prefilled name shows.
  const [optionsOpen, setOptionsOpen] = useState(host !== undefined);
  const remint = (asHub = hub) => {
    mutate({ ttl, labels: labelsOf(labels), name: name.trim() === '' ? undefined : name.trim(), hub: asHub });
  };

  return (
    <Modal className="dialog" labelledBy="add-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-title">Add a device</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <p className="muted">
        Run this on {host ? <>the device at {host.ip}</> : 'the device'} (Linux or macOS). It installs the agent,
        enrolls it with this hub and starts it.
      </p>

      <label className="hub-opt">
        <input
          type="checkbox"
          checked={hub}
          disabled={create.isPending}
          onChange={(e) => {
            setHub(e.target.checked);
            remint(e.target.checked);
          }}
        />
        <span>
          <strong>This device may become a hub</strong>
          <span className="muted small">
            A capable Linux device (64-bit, 2 GB of memory or more) also stores a copy of the data and, while the
            cluster has fewer than 3 masters, becomes a master and holds the CA key. Needs your password again.
          </span>
        </span>
      </label>

      {create.isError ? (
        <div className="error-box" role="alert">
          <p>Could not create an enrollment token: {create.error.message}</p>
          {tokenHub ? (
            <p className="muted small">Untick &ldquo;This device may become a hub&rdquo; to add it as a device only.</p>
          ) : null}
          <button
            className="btn"
            type="button"
            onClick={() => {
              remint();
            }}
          >
            Try again
          </button>
        </div>
      ) : null}

      {tok ? (
        <>
          <div className="add-grid">
            <div className="add-commands">
              <Command label="Install and join" value={tok.install_command} />
              <details className="alt">
                <summary>Hearth already installed?</summary>
                <Command label="Join only" value={tok.join_command} />
              </details>
              <p className="muted small">
                Single use · {tokenName ? <>joins as <strong>{tokenName}</strong> · </> : null}
                {tokenHub ? <>may become a hub · </> : null}expires at{' '}
                {new Date(tok.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </p>
              <details
                className="enroll-options"
                open={optionsOpen}
                onToggle={(e) => {
                  setOptionsOpen(e.currentTarget.open);
                }}
              >
                <summary>Name, expiry and labels</summary>
                <form
                  className="form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    remint();
                  }}
                >
                  <label className="field">
                    Device name
                    <input
                      value={name}
                      maxLength={63}
                      pattern="\s*[A-Za-z0-9][A-Za-z0-9._\-]*\s*"
                      title="Letters, digits, ., - or _, starting with a letter or digit"
                      placeholder="its hostname"
                      onChange={(e) => {
                        setName(e.target.value);
                      }}
                    />
                  </label>
                  <label className="field">
                    Token expires after
                    <select
                      value={ttl}
                      onChange={(e) => {
                        setTtl(e.target.value);
                      }}
                    >
                      {ttls.map((t) => (
                        <option key={t.value} value={t.value}>
                          {t.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <fieldset className="field label-rows">
                    <legend>Labels the device gets on enrollment</legend>
                    {labels.map((l, i) => (
                      <div key={i} className="label-row">
                        <input
                          aria-label="Label key"
                          placeholder="key, e.g. room"
                          value={l.key}
                          onChange={(e) => {
                            setLabels(labels.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)));
                          }}
                        />
                        <input
                          aria-label="Label value"
                          placeholder="value"
                          value={l.value}
                          onChange={(e) => {
                            setLabels(labels.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)));
                          }}
                        />
                        <button
                          className="btn btn-ghost btn-small"
                          type="button"
                          aria-label="Remove label"
                          onClick={() => {
                            setLabels(labels.filter((_, j) => j !== i));
                          }}
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                    <button
                      className="btn btn-small"
                      type="button"
                      onClick={() => {
                        setLabels([...labels, { key: '', value: '' }]);
                      }}
                    >
                      Add label
                    </button>
                  </fieldset>
                  <div className="settings-actions">
                    <button className="btn btn-primary btn-small" type="submit" disabled={create.isPending}>
                      New token with these options
                    </button>
                  </div>
                </form>
              </details>
            </div>
            <figure className="qr-wrap">
              <QrCode value={tok.install_command} label="QR code of the install command" />
              <figcaption className="muted small">Scan to copy on a phone</figcaption>
            </figure>
          </div>

          <div className={`waiting${joined ? ' waiting-done' : ''}`} aria-live="polite">
            {joined ? (
              <>
                <span className="dot dot-online" aria-hidden="true" />
                <span>
                  <strong>{displayName(joined)}</strong> joined.
                </span>
                <button
                  className="btn btn-primary"
                  type="button"
                  onClick={() => {
                    onShow(joined);
                  }}
                >
                  View device
                </button>
              </>
            ) : (
              <>
                <span className="pulse" aria-hidden="true" />
                <span className="muted">Waiting for the device to connect…</span>
              </>
            )}
          </div>
        </>
      ) : create.isPending ? (
        <p className="muted">Creating a single-use token…</p>
      ) : null}
    </Modal>
  );
}

type CopyState = 'idle' | 'copied' | 'selected';

const copyLabels: Record<CopyState, string> = {
  idle: 'Copy',
  copied: 'Copied',
  selected: 'Press Ctrl/⌘+C',
};

export function Command({ label, value }: { label: string; value: string }) {
  const [state, setState] = useState<CopyState>('idle');
  const pre = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (state === 'idle') {
      return;
    }
    const t = setTimeout(() => {
      setState('idle');
    }, 2500);
    return () => {
      clearTimeout(t);
    };
  }, [state]);

  // The clipboard API needs a secure context; the hub UI is often plain HTTP
  // on the LAN, so fall back to selecting the text for a manual copy.
  const selectText = () => {
    if (pre.current) {
      window.getSelection()?.selectAllChildren(pre.current);
      setState('selected');
    }
  };
  const copy = () => {
    if (!window.isSecureContext) {
      selectText();
      return;
    }
    navigator.clipboard.writeText(value).then(
      () => {
        setState('copied');
      },
      selectText,
    );
  };

  return (
    <div className="command">
      <div className="command-head">
        <span className="small muted">{label}</span>
        <button className="btn btn-small" type="button" onClick={copy}>
          {copyLabels[state]}
        </button>
      </div>
      <pre ref={pre} className="mono" tabIndex={0}>
        {value}
      </pre>
    </div>
  );
}
