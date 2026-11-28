import { useState } from 'react';
import { ApiError } from '../api/client.ts';
import {
  useInstallRegistryPlugin,
  usePluginRegistry,
  useRemoveRegistryPlugin,
  useUpdateRegistryPlugin,
  type InstalledPlugin,
  type PluginRegistry,
  type RegistryEntry,
} from '../api/pluginregistry.ts';
import { usePlugins } from '../api/plugins.ts';
import { formatDateTime } from '../format.ts';
import { classPill } from '../plugincommands.ts';
import { accessLines, accessSummary, browseState, matches } from '../pluginregistry.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { Tip } from './Tip.tsx';
import './PanelsPage.css';
import './SettingsPage.css';
import './DevicePluginsPage.css';

/** What a change's errors say, beyond the hub's own message. */
function changeError(err: Error): string | undefined {
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'reauth_cancelled':
        return undefined;
      case 'index_changed':
        return 'The plugin index changed since you opened this. Close, review the plugin again and retry.';
      case 'pin_mismatch':
        return `The module downloaded is not the one the signed index pins, so nothing was installed. ${err.message}`;
      case 'index_untrusted':
        return `The plugin index is not signed by a key this hub trusts, so nothing was installed. ${err.message}`;
      case 'forbidden':
        return 'Policy denies this.';
    }
  }
  return err.message;
}

type Dialog =
  | { kind: 'install'; entry: RegistryEntry }
  | { kind: 'update'; plugin: InstalledPlugin; entry: RegistryEntry }
  | { kind: 'remove'; plugin: InstalledPlugin };

/**
 * Settings → Plugins: the WASM plugins of a signed plugin index, to browse
 * and install on this hub, and those installed, to update or remove.
 */
export function PluginRegistryPage() {
  const q = usePluginRegistry();
  const [dialog, setDialog] = useState<Dialog>();
  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>
            Plugins <Tip id="plugins" />
          </h1>
          <p className="muted">WASM plugins from a signed plugin index, run in the hub’s sandbox.</p>
        </div>
      </div>
      <div className="settings">
        {q.isError ? (
          <div className="error-box" role="alert">
            Could not load the plugins: {q.error.message}
          </div>
        ) : !q.data ? (
          <p className="muted small">Loading…</p>
        ) : (
          <>
            <InstalledCard reg={q.data} onDialog={setDialog} />
            <BrowseCard reg={q.data} onDialog={setDialog} />
          </>
        )}
      </div>
      {dialog?.kind === 'install' ? (
        <InstallDialog
          entry={dialog.entry}
          onClose={() => {
            setDialog(undefined);
          }}
        />
      ) : dialog?.kind === 'update' ? (
        <InstallDialog
          entry={dialog.entry}
          from={dialog.plugin}
          onClose={() => {
            setDialog(undefined);
          }}
        />
      ) : dialog?.kind === 'remove' ? (
        <RemoveDialog
          plugin={dialog.plugin}
          onClose={() => {
            setDialog(undefined);
          }}
        />
      ) : null}
    </main>
  );
}

function InstalledCard({ reg, onDialog }: { reg: PluginRegistry; onDialog: (d: Dialog) => void }) {
  const status = usePlugins();
  const stateOf = (name: string) => status.data?.plugins.find((p) => p.name === name);
  return (
    <section className="panel-card" aria-labelledby="installed-title">
      <h2 id="installed-title" className="card-label">
        Installed
      </h2>
      {reg.installed.length === 0 ? (
        <p className="muted small">None yet. Install one from the index below.</p>
      ) : (
        <div className="table-wrap">
          <table className="devices network device-plugins">
            <thead>
              <tr>
                <th>Plugin</th>
                <th>Access</th>
                <th>State</th>
                <th>Installed</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {reg.installed.map((p) => {
                const s = stateOf(p.name);
                return (
                  <tr key={p.name}>
                    <td>
                      <span className="name">{p.name}</span> <span className="muted small mono">{p.version}</span>
                      {p.update ? (
                        <div>
                          <span className="pill pill-warn">Update available: {p.update.version}</span>
                        </div>
                      ) : null}
                      <div className="muted mono small" title={`SHA-256 ${p.sha256}`}>
                        {p.sha256.slice(0, 12)}
                      </div>
                    </td>
                    <td className="small">{accessSummary(p)}</td>
                    <td className="small">
                      {p.error ? (
                        <span className="pill pill-bad" title={p.error}>
                          not run
                        </span>
                      ) : s ? (
                        <span className={`pill ${s.state === 'running' ? 'pill-ok' : 'pill-warn'}`} title={s.error}>
                          {s.state}
                        </span>
                      ) : (
                        <span className="muted">starting…</span>
                      )}
                      {p.error ? <div className="muted">{p.error}</div> : null}
                    </td>
                    <td className="small">
                      {formatDateTime(p.installed_at)}
                      {p.installed_by ? <div className="muted">by {p.installed_by}</div> : null}
                    </td>
                    <td>
                      <div className="row-actions">
                        {p.update ? (
                          <button
                            type="button"
                            className="btn btn-small"
                            disabled={reg.decisions.update === 'deny'}
                            onClick={() => {
                              if (p.update) {
                                onDialog({ kind: 'update', plugin: p, entry: p.update });
                              }
                            }}
                          >
                            Update
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="btn btn-ghost btn-small"
                          disabled={reg.decisions.remove === 'deny'}
                          onClick={() => {
                            onDialog({ kind: 'remove', plugin: p });
                          }}
                        >
                          Remove
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function BrowseCard({ reg, onDialog }: { reg: PluginRegistry; onDialog: (d: Dialog) => void }) {
  const [query, setQuery] = useState('');
  if (!reg.enabled) {
    return (
      <section className="panel-card" aria-labelledby="browse-title">
        <h2 id="browse-title" className="card-label">
          Browse
        </h2>
        <p className="muted small">
          No plugin index is configured, so there is nothing to browse. Start the hub with{' '}
          <code>--plugin-index URL-or-file</code> and <code>--plugin-index-key KEY</code>: the hub installs only from
          an index signed with a key you trust.
        </p>
      </section>
    );
  }
  const shown = reg.available.filter((e) => matches(e, query));
  return (
    <section className="panel-card" aria-labelledby="browse-title">
      <div className="panel-card-head">
        <h2 id="browse-title" className="card-label">
          Browse
        </h2>
        <input
          type="search"
          className="registry-search"
          placeholder="Search plugins"
          aria-label="Search plugins"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
          }}
        />
      </div>
      <p className="muted small">
        From <span className="mono">{reg.source}</span>, signed with key{reg.keys.length > 1 ? 's' : ''}{' '}
        <span className="mono">{reg.keys.join(', ')}</span>.
      </p>
      {reg.index_error ? (
        <div className="error-box" role="alert">
          The plugin index cannot be used: {reg.index_error}
        </div>
      ) : shown.length === 0 ? (
        <p className="muted small">{reg.available.length === 0 ? 'The index lists no plugins.' : 'No plugin matches.'}</p>
      ) : (
        <ul className="registry-list">
          {shown.map((e) => {
            const state = browseState(e, reg.installed);
            const installed = reg.installed.find((p) => p.name === e.name);
            return (
              <li key={e.name} className="registry-item">
                <div className="registry-item-head">
                  <div>
                    <span className="name">{e.name}</span> <span className="muted small mono">{e.version}</span>
                    {e.description ? <div className="small">{e.description}</div> : null}
                    <div className="muted small">
                      {[e.author, e.license].filter(Boolean).join(' · ')}
                      {e.homepage ? (
                        <>
                          {e.author || e.license ? ' · ' : ''}
                          <a href={e.homepage} target="_blank" rel="noreferrer">
                            homepage
                          </a>
                        </>
                      ) : null}
                    </div>
                  </div>
                  {state === 'install' ? (
                    <button
                      type="button"
                      className="btn btn-primary btn-small"
                      disabled={reg.decisions.install === 'deny'}
                      title={reg.decisions.install === 'deny' ? 'Policy denies installing plugins' : undefined}
                      onClick={() => {
                        onDialog({ kind: 'install', entry: e });
                      }}
                    >
                      Install
                    </button>
                  ) : state === 'update' && installed ? (
                    <button
                      type="button"
                      className="btn btn-small"
                      disabled={reg.decisions.update === 'deny'}
                      onClick={() => {
                        onDialog({ kind: 'update', plugin: installed, entry: e });
                      }}
                    >
                      Update to {e.version}
                    </button>
                  ) : (
                    <span className="pill pill-muted">Installed</span>
                  )}
                </div>
                <div className="device-plugins-commands">
                  <span className="pill pill-muted">{accessSummary(e)}</span>
                  {e.commands.map((c) => (
                    <span key={c.name} className={`pill ${classPill[c.class]}`} title={c.description}>
                      {c.name} · {c.class}
                    </span>
                  ))}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/** Shows everything the plugin asks for, then installs or updates it once confirmed and re-authenticated. */
function InstallDialog({ entry, from, onClose }: { entry: RegistryEntry; from?: InstalledPlugin; onClose: () => void }) {
  const install = useInstallRegistryPlugin();
  const update = useUpdateRegistryPlugin();
  const m = from ? update : install;
  const verb = from ? 'Update' : 'Install';
  return (
    <ConfirmDialog
      title={from ? `Update ${entry.name} ${from.version} to ${entry.version}` : `Install ${entry.name} ${entry.version}`}
      actionClass="dangerous"
      confirmLabel={verb}
      pendingLabel={from ? 'Updating…' : 'Installing…'}
      pending={m.isPending}
      asksPassword
      error={m.isError ? changeError(m.error) : undefined}
      done={m.isSuccess ? `${from ? 'Updated' : 'Installed'} ${entry.name} ${entry.version}. The hub starts it now.` : undefined}
      onConfirm={() => {
        m.mutate({ name: entry.name, version: entry.version, sha256: entry.sha256, digest: entry.digest });
      }}
      onClose={onClose}
    >
      <p>
        Runs third-party code in the hub’s WASM sandbox. Once installed, {entry.name} may only:
      </p>
      <ul className="registry-access">
        {accessLines(entry).map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
      {entry.commands.length > 0 ? (
        <>
          <p className="small">Commands it offers, each decided by policy at its class:</p>
          <div className="device-plugins-commands">
            {entry.commands.map((c) => (
              <span key={c.name} className={`pill ${classPill[c.class]}`} title={c.description}>
                {c.name} · {c.class}
              </span>
            ))}
          </div>
        </>
      ) : null}
      <p className="muted small mono" title="The module's SHA-256, pinned by the signed index">
        sha256 {entry.sha256}
      </p>
    </ConfirmDialog>
  );
}

function RemoveDialog({ plugin, onClose }: { plugin: InstalledPlugin; onClose: () => void }) {
  const del = useRemoveRegistryPlugin();
  return (
    <ConfirmDialog
      title={`Remove ${plugin.name} ${plugin.version}`}
      actionClass="safe"
      confirmLabel="Remove"
      pendingLabel="Removing…"
      pending={del.isPending}
      error={del.isError ? changeError(del.error) : undefined}
      done={del.isSuccess ? `Removed ${plugin.name}.` : undefined}
      onConfirm={() => {
        del.mutate(plugin.name);
      }}
      onClose={onClose}
    >
      <p>Stops the plugin and deletes its module from this hub. Automations that use its commands fail until it is back.</p>
    </ConfirmDialog>
  );
}
