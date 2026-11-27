import { useState } from 'react';
import { useAddUniFiController, type UniFiController, type UniFiKind } from '../api/unifi.ts';
import { validFingerprint } from '../unifi.ts';
import { Modal } from './Modal.tsx';
import './PanelsPage.css';

interface Props {
  onClose: () => void;
  onAdded: (c: UniFiController) => void;
}

type SignIn = 'api_key' | 'password';

export function AddUniFiDialog({ onClose, onAdded }: Props) {
  const add = useAddUniFiController();
  const [name, setName] = useState('');
  const [url, setURL] = useState('');
  const [kind, setKind] = useState<UniFiKind>('unifi_os');
  const [signIn, setSignIn] = useState<SignIn>('api_key');
  const [apiKey, setAPIKey] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [site, setSite] = useState('default');
  const [fingerprint, setFingerprint] = useState('');

  // A self-hosted controller has no API key: it signs in with a local login.
  const withKey = kind === 'unifi_os' && signIn === 'api_key';
  const ready =
    name.trim() !== '' &&
    url.trim() !== '' &&
    (withKey ? apiKey.trim() !== '' : username.trim() !== '' && password !== '') &&
    validFingerprint(fingerprint);

  return (
    <Modal className="dialog" labelledBy="add-unifi-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-unifi-title">Connect a UniFi controller</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <p className="muted">
        Hearth reads the site's gateways, switches, access points and clients through the UniFi Network API. It installs
        nothing there. Use a key or a local account of its own, read-only if you never restart access points from Hearth.
        The credentials are kept encrypted on the hub and never shown again.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate(
            {
              name: name.trim(),
              url: url.trim(),
              kind,
              site: site.trim(),
              api_key: withKey ? apiKey.trim() : '',
              username: withKey ? '' : username.trim(),
              password: withKey ? '' : password,
              fingerprint: fingerprint.trim(),
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
            placeholder="home"
            maxLength={63}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Controller</span>
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as UniFiKind);
            }}
          >
            <option value="unifi_os">UniFi OS console (Dream Machine, Cloud Gateway, Cloud Key Gen2+)</option>
            <option value="classic">Self-hosted UniFi Network application</option>
          </select>
        </label>
        <label className="field">
          <span>Controller URL</span>
          <input
            required
            value={url}
            placeholder={kind === 'unifi_os' ? 'https://192.168.1.1' : 'https://unifi.lan:8443'}
            autoCapitalize="none"
            spellCheck={false}
            onChange={(e) => {
              setURL(e.target.value);
            }}
          />
        </label>
        {kind === 'unifi_os' ? (
          <label className="field">
            <span>Sign in with</span>
            <select
              value={signIn}
              onChange={(e) => {
                setSignIn(e.target.value as SignIn);
              }}
            >
              <option value="api_key">An API key (Network settings → Integrations)</option>
              <option value="password">A local username and password</option>
            </select>
          </label>
        ) : null}
        {withKey ? (
          <label className="field">
            <span>API key</span>
            <input
              required
              type="password"
              className="mono"
              value={apiKey}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => {
                setAPIKey(e.target.value);
              }}
            />
          </label>
        ) : (
          <>
            <label className="field">
              <span>Username (a local account, not a UI.com one)</span>
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
          </>
        )}
        <label className="field">
          <span>Site (its short name, as in /network/&lt;name&gt;/ or /manage/site/&lt;name&gt;/)</span>
          <input
            className="mono"
            value={site}
            autoCapitalize="none"
            spellCheck={false}
            onChange={(e) => {
              setSite(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Certificate fingerprint (SHA-256, for the controller's self-signed certificate)</span>
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
            {add.isPending ? 'Connecting…' : 'Connect controller'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
