import { useState } from 'react';
import { useAddProxmoxServer, type ProxmoxServer } from '../api/proxmox.ts';
import { Modal } from './Modal.tsx';

type Trust = 'fingerprint' | 'ca' | 'system';

interface Props {
  onClose: () => void;
  onAdded: (s: ProxmoxServer) => void;
}

export function AddProxmoxDialog({ onClose, onAdded }: Props) {
  const add = useAddProxmoxServer();
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  const [trust, setTrust] = useState<Trust>('fingerprint');
  const [fingerprint, setFingerprint] = useState('');
  const [caPem, setCaPem] = useState('');

  const trustSet = trust === 'system' || (trust === 'ca' ? caPem.trim() !== '' : fingerprint.trim() !== '');
  const ready = name.trim() !== '' && url.trim() !== '' && token.trim() !== '' && trustSet;

  return (
    <Modal className="dialog" labelledBy="add-proxmox-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-proxmox-title">Add a Proxmox server</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <p className="muted">
        Create an API token under <strong>Datacenter → Permissions → API Tokens</strong>. It is kept encrypted on the hub and
        never shown again.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate(
            {
              name: name.trim(),
              url: url.trim(),
              token: token.trim(),
              ca_pem: trust === 'ca' ? caPem : '',
              fingerprint: trust === 'fingerprint' ? fingerprint.trim() : '',
            },
            { onSuccess: onAdded },
          );
        }}
      >
        <label className="field">
          <span>Name</span>
          <input
            required
            value={name}
            placeholder="homelab"
            maxLength={63}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Address</span>
          <input
            required
            value={url}
            placeholder="https://pve.lan:8006"
            inputMode="url"
            autoCapitalize="none"
            spellCheck={false}
            onChange={(e) => {
              setUrl(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>API token</span>
          <input
            required
            type="password"
            className="mono"
            value={token}
            placeholder="user@pam!tokenid=secret"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => {
              setToken(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Verify the server's certificate with</span>
          <select
            value={trust}
            onChange={(e) => {
              setTrust(e.target.value as Trust);
            }}
          >
            <option value="fingerprint">Its SHA-256 fingerprint</option>
            <option value="ca">A CA certificate</option>
            <option value="system">The hub's system CAs</option>
          </select>
        </label>
        {trust === 'fingerprint' ? (
          <label className="field">
            <span>SHA-256 fingerprint</span>
            <input
              required
              className="mono"
              value={fingerprint}
              placeholder="AB:CD:EF:…"
              autoCapitalize="none"
              spellCheck={false}
              onChange={(e) => {
                setFingerprint(e.target.value);
              }}
            />
          </label>
        ) : null}
        {trust === 'ca' ? (
          <>
            <label className="field">
              <span>CA certificate (PEM)</span>
              <textarea
                required
                rows={6}
                spellCheck={false}
                className="mono"
                value={caPem}
                placeholder="-----BEGIN CERTIFICATE-----"
                onChange={(e) => {
                  setCaPem(e.target.value);
                }}
              />
            </label>
            <label className="file-pick small">
              <span className="muted">or load /etc/pve/pve-root-ca.pem:</span>
              <input
                type="file"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) {
                    void f.text().then(setCaPem);
                  }
                }}
              />
            </label>
          </>
        ) : null}
        {add.isError ? (
          <div className="error-box" role="alert">
            {add.error.message}
          </div>
        ) : null}
        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" disabled={add.isPending || !ready}>
            {add.isPending ? 'Adding…' : 'Add server'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
