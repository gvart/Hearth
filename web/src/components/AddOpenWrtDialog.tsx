import { useState } from 'react';
import { useAddOpenWrtRouter, type OpenWrtRouter } from '../api/openwrt.ts';
import { isPlainHTTP, validFingerprint } from '../openwrt.ts';
import { Modal } from './Modal.tsx';
import './PanelsPage.css';

interface Props {
  onClose: () => void;
  onAdded: (r: OpenWrtRouter) => void;
}

export function AddOpenWrtDialog({ onClose, onAdded }: Props) {
  const add = useAddOpenWrtRouter();
  const [name, setName] = useState('');
  const [url, setURL] = useState('');
  const [username, setUsername] = useState('root');
  const [password, setPassword] = useState('');
  const [fingerprint, setFingerprint] = useState('');

  const plain = isPlainHTTP(url);
  const ready =
    name.trim() !== '' && url.trim() !== '' && username.trim() !== '' && password !== '' && validFingerprint(fingerprint);

  return (
    <Modal className="dialog" labelledBy="add-openwrt-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-openwrt-title">Connect an OpenWrt router</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <p className="muted">
        Hearth logs in to the router's ubus (the API LuCI uses) and reads its clients, interfaces and system info. It
        installs nothing there. Use a login of its own with a read-only rpcd ACL: see the docs. The password is kept
        encrypted on the hub and never shown again.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate(
            {
              name: name.trim(),
              url: url.trim(),
              username: username.trim(),
              password,
              fingerprint: plain ? '' : fingerprint.trim(),
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
            placeholder="gateway"
            maxLength={63}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Router URL</span>
          <input
            required
            value={url}
            placeholder="https://192.168.1.1"
            autoCapitalize="none"
            spellCheck={false}
            onChange={(e) => {
              setURL(e.target.value);
            }}
          />
        </label>
        {plain ? (
          <p className="muted small" role="note">
            Plain http sends the password across your network in the clear. Prefer https if the router serves it.
          </p>
        ) : null}
        <label className="field">
          <span>Username</span>
          <input
            required
            value={username}
            autoCapitalize="none"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => {
              setUsername(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Password</span>
          <input
            required
            type="password"
            value={password}
            autoComplete="off"
            onChange={(e) => {
              setPassword(e.target.value);
            }}
          />
        </label>
        {!plain ? (
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
            {add.isPending ? 'Connecting…' : 'Connect router'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
