import { useEffect, useRef, useState } from 'react';
import type { Device } from '../api/client.ts';
import { useCreateToken } from '../api/hooks.ts';
import { displayName } from '../format.ts';
import { Modal } from './Modal.tsx';
import { QrCode } from './QrCode.tsx';

interface Props {
  /** The first device that appeared since the dialog opened, if any. */
  joined: Device | undefined;
  onClose: () => void;
  onShow: (d: Device) => void;
}

export function AddDeviceDialog({ joined, onClose, onShow }: Props) {
  const create = useCreateToken();
  const { mutate } = create;
  // Guards against StrictMode's double effect minting two tokens.
  const requested = useRef(false);
  useEffect(() => {
    if (!requested.current) {
      requested.current = true;
      mutate({});
    }
  }, [mutate]);

  const tok = create.data;

  return (
    <Modal className="dialog" labelledBy="add-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-title">Add a device</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <p className="muted">
        Run this on the device (Linux or macOS). It installs the agent, enrolls it with this hub and starts it.
      </p>

      {create.isError ? (
        <div className="error-box" role="alert">
          <p>Could not create an enrollment token: {create.error.message}</p>
          <button
            className="btn"
            type="button"
            onClick={() => {
              mutate({});
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
                Single use · expires at {new Date(tok.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </p>
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

function Command({ label, value }: { label: string; value: string }) {
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
