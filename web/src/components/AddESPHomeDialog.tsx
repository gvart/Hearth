import { useState } from 'react';
import { useAddESPHomeDevice, type ESPHomeDevice } from '../api/esphome.ts';
import { validKey } from '../esphome.ts';
import { Modal } from './Modal.tsx';
import './PanelsPage.css';

type Mode = 'noise' | 'plaintext';

interface Props {
  onClose: () => void;
  onAdded: (d: ESPHomeDevice) => void;
  /** Prefilled from a discovered host. */
  initial?: { name: string; address: string };
}

export function AddESPHomeDialog({ onClose, onAdded, initial }: Props) {
  const add = useAddESPHomeDevice();
  const [name, setName] = useState(initial?.name ?? '');
  const [address, setAddress] = useState(initial?.address ?? '');
  const [mode, setMode] = useState<Mode>('noise');
  const [key, setKey] = useState('');
  const [password, setPassword] = useState('');
  const [control, setControl] = useState(false);

  const keyOk = mode === 'plaintext' || validKey(key);
  const ready = name.trim() !== '' && address.trim() !== '' && keyOk;

  return (
    <Modal className="dialog" labelledBy="add-esphome-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-esphome-title">Adopt an ESPHome device</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <p className="muted">
        Hearth connects to the device's native API, as Home Assistant does, and installs nothing on it. Its encryption key
        is under <code>api: encryption: key:</code> in the device's YAML. It is kept encrypted on the hub and never shown
        again.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate(
            {
              name: name.trim(),
              address: address.trim(),
              key: mode === 'noise' ? key.trim() : '',
              password: mode === 'plaintext' ? password : '',
              control,
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
            placeholder="kitchen-sensor"
            maxLength={63}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>IP address</span>
          <input
            required
            value={address}
            placeholder="192.168.1.40 (port 6053 unless you give one)"
            autoCapitalize="none"
            spellCheck={false}
            onChange={(e) => {
              setAddress(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Connection</span>
          <select
            value={mode}
            onChange={(e) => {
              setMode(e.target.value as Mode);
            }}
          >
            <option value="noise">Encrypted with the API key</option>
            <option value="plaintext">Not encrypted (older setups)</option>
          </select>
        </label>
        {mode === 'noise' ? (
          <label className="field">
            <span>API encryption key</span>
            <input
              required
              type="password"
              className="mono"
              value={key}
              placeholder="base64, 44 characters"
              autoComplete="off"
              spellCheck={false}
              aria-invalid={key !== '' && !validKey(key) ? true : undefined}
              onChange={(e) => {
                setKey(e.target.value);
              }}
            />
          </label>
        ) : (
          <label className="field">
            <span>API password (firmware before 2026.1; leave empty if none)</span>
            <input
              type="password"
              value={password}
              autoComplete="off"
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />
          </label>
        )}
        <label className="check">
          <input
            type="checkbox"
            checked={control}
            onChange={(e) => {
              setControl(e.target.checked);
            }}
          />
          <span>
            Allow switch and button calls
            <span className="muted small"> Off: Hearth only reads the device. Each call is a policy decision, audited.</span>
          </span>
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
            {add.isPending ? 'Adopting…' : 'Adopt device'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
