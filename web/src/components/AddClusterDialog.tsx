import { useState } from 'react';
import type { KubeCluster } from '../api/client.ts';
import { useAddKubeCluster } from '../api/hooks.ts';
import { Modal } from './Modal.tsx';

interface Props {
  onClose: () => void;
  onAdded: (c: KubeCluster) => void;
}

export function AddClusterDialog({ onClose, onAdded }: Props) {
  const add = useAddKubeCluster();
  const [name, setName] = useState('');
  const [kubeconfig, setKubeconfig] = useState('');

  return (
    <Modal className="dialog" labelledBy="add-cluster-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="add-cluster-title">Add a Kubernetes cluster</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      <p className="muted">
        Paste a kubeconfig, for example from <code>talosctl kubeconfig -</code>, <code>/etc/rancher/k3s/k3s.yaml</code> or{' '}
        <code>kind get kubeconfig</code>. Only its current context is kept, encrypted on the hub. Hearth only reads from the
        cluster.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate(
            { name: name.trim(), kubeconfig },
            {
              onSuccess: onAdded,
            },
          );
        }}
      >
        <label className="field">
          <span>Name</span>
          <input
            value={name}
            placeholder="Defaults to the context name"
            maxLength={63}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        </label>
        <label className="field">
          <span>Kubeconfig</span>
          <textarea
            required
            rows={10}
            spellCheck={false}
            className="mono"
            value={kubeconfig}
            placeholder="apiVersion: v1&#10;kind: Config&#10;…"
            aria-invalid={add.isError}
            onChange={(e) => {
              setKubeconfig(e.target.value);
            }}
          />
        </label>
        <label className="file-pick small">
          <span className="muted">or load a file:</span>
          <input
            type="file"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) {
                void f.text().then(setKubeconfig);
              }
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
          <button className="btn btn-primary" type="submit" disabled={add.isPending || kubeconfig.trim() === ''}>
            {add.isPending ? 'Adding…' : 'Add cluster'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
