import { useState } from 'react';
import { useAddOPNsenseFirewall, type OPNsenseFirewall } from '../api/opnsense.ts';
import { validFingerprint } from '../openwrt.ts';
import { isPlainHTTP } from '../opnsense.ts';
import { Modal } from './Modal.tsx';
import './PanelsPage.css';

interface Props {
  onClose: () => void;
  onAdded: (f: OPNsenseFirewall) => void;
}

export function AddOPNsenseDialog({ onClose, onAdded }: Props) {
  const add = useAddOPNsenseFirewall();
  const [name, setName] = useState('');
  const [url, setURL] = useState('');
  const [key, setKey] = useState('');
  const [secret, setSecret] = useState('');
  const [fingerprint, setFingerprint] = useState('');

  const plain = isPlainHTTP(url);
  const ready =
    name.trim() !== '' &&
    url.trim() !== '' &&
    !plain &&
    key.trim() !== '' &&
    secret.trim() !== '' &&
    validFingerprint(fingerprint);

  return (
    <Modal className="dialog" labelledBy="add-opnsense-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-opnsense-title">Connect an OPNsense firewall</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <p className="muted">
        Hearth calls the firewall's REST API with an API key and reads its DHCP leases, ARP table, interface traffic and
        system info. It installs nothing there. Make the key for a user of its own with only the privileges Hearth
        needs: see the docs. The key and secret are kept encrypted on the hub and never shown again.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate(
            { name: name.trim(), url: url.trim(), key: key.trim(), secret: secret.trim(), fingerprint: fingerprint.trim() },
            { onSuccess: onAdded },
          );
        }}
      >
        <label className="field">
          <span>Name</span>
          <input
            required
            value={name}
            placeholder="edge"
            maxLength={63}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Firewall URL</span>
          <input
            required
            value={url}
            placeholder="https://192.168.1.1"
            autoCapitalize="none"
            spellCheck={false}
            aria-invalid={plain ? true : undefined}
            onChange={(e) => {
              setURL(e.target.value);
            }}
          />
        </label>
        {plain ? (
          <p className="muted small" role="note">
            Use https: every request carries the API key, which plain http would send across your network in the clear.
          </p>
        ) : null}
        <label className="field">
          <span>API key</span>
          <input
            required
            className="mono"
            value={key}
            autoCapitalize="none"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => {
              setKey(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>API secret</span>
          <input
            required
            type="password"
            value={secret}
            autoComplete="off"
            onChange={(e) => {
              setSecret(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Certificate fingerprint (SHA-256, for a self-signed certificate)</span>
          <input
            className="mono"
            value={fingerprint}
            placeholder="AA:BB:… (empty: trusted by the system)"
            autoCapitalize="none"
            spellCheck={false}
            aria-invalid={!validFingerprint(fingerprint) ? true : undefined}
            onChange={(e) => {
              setFingerprint(e.target.value);
            }}
          />
        </label>
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
            {add.isPending ? 'Connecting…' : 'Connect firewall'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
