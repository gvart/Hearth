import { useState, type SyntheticEvent } from 'react';
import { ApiError } from '../api/client.ts';
import {
  uploadArches,
  uploadOSes,
  useDeleteDevicePlugin,
  useDevicePluginRegistry,
  useUploadDevicePlugin,
  type DevicePlugin,
} from '../api/deviceplugins.ts';
import { classPill } from '../plugincommands.ts';
import { formatBytes, formatDateTime } from '../format.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { Tip } from './Tip.tsx';
import './PanelsPage.css';
import './SettingsPage.css';

/** What the upload's errors say, beyond the hub's own message. */
function uploadError(err: Error): string {
  if (err instanceof ApiError && err.code === 'too_large') {
    return `The program is larger than the hub takes. ${err.message}`;
  }
  if (err instanceof ApiError && err.code === 'schema_too_old') {
    return `The hub's store is too old for device plugins. ${err.message}`;
  }
  return err.message;
}

/**
 * The exec plugins the hub hands to devices: uploaded here as a manifest and
 * a program per platform, then granted to a device under its Capabilities.
 */
export function DevicePluginsPage() {
  const q = useDevicePluginRegistry();
  const [deleting, setDeleting] = useState<DevicePlugin>();
  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>
            Device plugins <Tip id="deviceplugins" />
          </h1>
          <p className="muted">Programs the hub sends to devices, to run their commands there.</p>
        </div>
      </div>
      <div className="settings">
        <UploadCard maxSize={q.data?.max_size} />
        <section className="panel-card" aria-labelledby="registry-title">
          <h2 id="registry-title" className="card-label">
            Uploaded
          </h2>
          {q.isError ? (
            <div className="error-box" role="alert">
              Could not load the device plugins: {q.error.message}
            </div>
          ) : !q.data ? (
            <p className="muted small">Loading…</p>
          ) : q.data.plugins.length === 0 ? (
            <p className="muted small">None yet. Upload one above, then grant it to a device under Capabilities.</p>
          ) : (
            <div className="table-wrap">
              <table className="devices network">
                <thead>
                  <tr>
                    <th>Plugin</th>
                    <th>Platform</th>
                    <th>Size</th>
                    <th>Commands</th>
                    <th>Uploaded</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {q.data.plugins.map((p) => (
                    <tr key={p.id}>
                      <td>
                        <span className="name">{p.name}</span> <span className="muted small mono">{p.version}</span>
                      </td>
                      <td className="mono small">
                        {p.os}/{p.arch}
                      </td>
                      <td className="small">
                        {formatBytes(p.size)}{' '}
                        <span className="muted mono" title={p.sha256}>
                          {p.sha256.slice(0, 12)}
                        </span>
                      </td>
                      <td>
                        {p.commands.map((c) => (
                          <span key={c.name} className={`pill ${classPill[c.class]}`} title={c.description}>
                            {c.name} · {c.class}
                          </span>
                        ))}
                      </td>
                      <td className="small">
                        {formatDateTime(p.uploaded_at)}
                        {p.uploaded_by ? <span className="muted"> by {p.uploaded_by}</span> : null}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-ghost btn-small"
                          onClick={() => {
                            setDeleting(p);
                          }}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
      {deleting ? (
        <DeleteDialog
          plugin={deleting}
          onClose={() => {
            setDeleting(undefined);
          }}
        />
      ) : null}
    </main>
  );
}

function UploadCard({ maxSize }: { maxSize?: number }) {
  const upload = useUploadDevicePlugin();
  const [manifest, setManifest] = useState<File>();
  const [program, setProgram] = useState<File>();
  const [os, setOS] = useState<string>('linux');
  const [arch, setArch] = useState<string>('arm64');
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (manifest && program) {
      upload.mutate({ manifest, program, os, arch });
    }
  };
  const cancelled = upload.error instanceof ApiError && upload.error.code === 'reauth_cancelled';
  return (
    <section className="panel-card" aria-labelledby="upload-title">
      <h2 id="upload-title" className="card-label">
        Upload a plugin
      </h2>
      <form className="form" onSubmit={submit}>
        <label className="field">
          <span>
            Manifest <span className="muted small">(plugin.yaml)</span>
          </span>
          <input
            type="file"
            accept=".yaml,.yml,text/yaml,text/plain"
            required
            onChange={(e) => {
              setManifest(e.target.files?.[0]);
            }}
          />
        </label>
        <label className="field">
          <span>
            Program{' '}
            <span className="muted small">
              (built for the platform below{maxSize ? `, up to ${formatBytes(maxSize)}` : ''})
            </span>
          </span>
          <input
            type="file"
            required
            onChange={(e) => {
              setProgram(e.target.files?.[0]);
            }}
          />
        </label>
        <label className="field">
          <span>OS</span>
          <select
            value={os}
            onChange={(e) => {
              setOS(e.target.value);
            }}
          >
            {uploadOSes.map((o) => (
              <option key={o}>{o}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Architecture</span>
          <select
            value={arch}
            onChange={(e) => {
              setArch(e.target.value);
            }}
          >
            {uploadArches.map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
        </label>
        {upload.isError && !cancelled ? (
          <div className="error-box" role="alert">
            {uploadError(upload.error)}
          </div>
        ) : null}
        {upload.isSuccess ? (
          <div className="ok-box" role="status">
            Uploaded {upload.data.name} {upload.data.version} for {upload.data.os}/{upload.data.arch}.
          </div>
        ) : null}
        <div className="form-actions">
          <button className="btn btn-primary" type="submit" disabled={!manifest || !program || upload.isPending}>
            {upload.isPending ? 'Uploading…' : 'Upload'}
          </button>
        </div>
      </form>
    </section>
  );
}

function DeleteDialog({ plugin, onClose }: { plugin: DevicePlugin; onClose: () => void }) {
  const del = useDeleteDevicePlugin();
  return (
    <ConfirmDialog
      title={`Delete ${plugin.name} ${plugin.version}`}
      actionClass="dangerous"
      confirmLabel="Delete"
      pendingLabel="Deleting…"
      pending={del.isPending}
      error={del.isError ? del.error.message : undefined}
      done={del.isSuccess ? `Deleted ${plugin.name} for ${plugin.os}/${plugin.arch}.` : undefined}
      onConfirm={() => {
        del.mutate(plugin.id);
      }}
      onClose={onClose}
    >
      <p>
        Removes the {plugin.os}/{plugin.arch} build from the hub.
      </p>
    </ConfirmDialog>
  );
}
