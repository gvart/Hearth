import { useState } from 'react';
import type { CreatedPanelLink, Device, Panel, PanelInput } from '../api/client.ts';
import {
  useCreatePanelLink,
  useDeletePanel,
  useDevices,
  usePanels,
  useRevokePanelLink,
  useSavePanel,
  useShareOrigin,
} from '../api/hooks.ts';
import { displayName, formatDateTime, statusLabel } from '../format.ts';
import { addDevice, linkExpiries, moveWidget, restartServices, shareURL, toggleRestart, toInput } from '../panels.ts';
import { Command } from './AddDeviceDialog.tsx';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { DashboardTokens } from './DashboardTokens.tsx';
import { Modal } from './Modal.tsx';
import { StatusDot } from './StatusDot.tsx';
import './PanelsPage.css';
import { Tip } from './Tip.tsx';

/**
 * Guest and kiosk panels: a few devices and the restarts a guest may take on
 * them, opened by a share link with no login (docs/panels.md).
 */
export function PanelsPage() {
  const panels = usePanels();
  const devices = useDevices();
  const [editing, setEditing] = useState<Panel | 'new' | null>(null);
  const [sharing, setSharing] = useState<Panel | null>(null);
  const list = panels.data ?? [];
  const byId = new Map((devices.data ?? []).map((d) => [d.id, d]));

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>
            Panels <Tip id="panels" />
          </h1>
          <p className="muted">
            A wall screen or a guest page: chosen devices and the restarts allowed on them, opened by a link with no
            login.
          </p>
        </div>
        <button
          className="btn btn-primary"
          type="button"
          onClick={() => {
            setEditing('new');
          }}
        >
          New panel
        </button>
      </div>

      {panels.isError ? (
        <div className="error-box" role="alert">
          Could not load panels: {panels.error.message}
        </div>
      ) : panels.isPending ? (
        <p className="muted">Loading panels…</p>
      ) : list.length === 0 ? (
        <div className="empty">
          <h2>No panels yet</h2>
          <p className="muted">
            Build one with the devices a guest or a wall screen should see, then share it. Guests can only take the
            restarts you allow, and the hub&apos;s policy decides each one again.
          </p>
        </div>
      ) : (
        <div className="panel-list">
          {list.map((p) => (
            <PanelCard
              key={p.id}
              panel={p}
              devices={byId}
              onEdit={() => {
                setEditing(p);
              }}
              onShare={() => {
                setSharing(p);
              }}
            />
          ))}
        </div>
      )}

      <DashboardTokens />

      {editing ? (
        <PanelEditor
          panel={editing === 'new' ? undefined : editing}
          devices={devices.data ?? []}
          onClose={() => {
            setEditing(null);
          }}
        />
      ) : null}
      {sharing ? (
        <ShareDialog
          panel={sharing}
          onClose={() => {
            setSharing(null);
          }}
        />
      ) : null}
    </main>
  );
}

function PanelCard({
  panel,
  devices,
  onEdit,
  onShare,
}: {
  panel: Panel;
  devices: Map<string, Device>;
  onEdit: () => void;
  onShare: () => void;
}) {
  const del = useDeletePanel();
  const revoke = useRevokePanelLink();
  const active = panel.links.filter((l) => l.status === 'active');
  const [deleting, setDeleting] = useState(false);
  const buttons = panel.widgets.reduce((n, w) => n + w.actions.length, 0);

  return (
    <section className="panel-card" aria-labelledby={`panel-${panel.id}`}>
      <div className="panel-card-head">
        <h2 id={`panel-${panel.id}`}>{panel.name}</h2>
        <div className="row-actions">
          <button className="btn btn-small" type="button" onClick={onEdit}>
            Edit
          </button>
          <button className="btn btn-small btn-primary" type="button" onClick={onShare}>
            Share
          </button>
          <button
            className="btn btn-small btn-ghost"
            type="button"
            disabled={del.isPending}
            onClick={() => {
              setDeleting(true);
            }}
          >
            Delete
          </button>
        </div>
      </div>
      {panel.widgets.length === 0 ? (
        <p className="muted small">No devices yet.</p>
      ) : (
        <>
          <div className="panel-preview" role="img" aria-label={`What a guest sees on ${panel.name}`}>
            {panel.widgets.map((w) => {
              const d = devices.get(w.entity);
              const status = d?.status ?? 'unknown';
              return (
                <div key={w.id} className={status === 'online' ? 'mini-tile' : 'mini-tile mini-tile-off'}>
                  <span className="mini-tile-head">
                    <StatusDot status={status} />
                    <span className="name">{d ? displayName(d) : w.entity}</span>
                  </span>
                  <span className="muted small">{statusLabel(status)}</span>
                  {w.actions.map((a) => (
                    <span key={a.id} className="mini-btn">
                      Restart {a.service}
                    </span>
                  ))}
                </div>
              );
            })}
          </div>
          <p className="muted small">
            What a guest sees: {panel.widgets.length} device{panel.widgets.length === 1 ? '' : 's'}
            {buttons > 0 ? ` and ${String(buttons)} button${buttons === 1 ? '' : 's'}` : ', status only'}.
          </p>
        </>
      )}
      <h3 className="panel-links-head">
        Share links <span className="muted small">({active.length} active)</span>
      </h3>
      {panel.links.length === 0 ? (
        <p className="muted small">Not shared.</p>
      ) : (
        <ul className="panel-links">
          {panel.links.map((l) => (
            <li key={l.id}>
              <span className={`pill ${l.status === 'active' ? 'pill-ok' : 'pill-muted'}`}>{l.status}</span>
              <span className="small muted">
                created {formatDateTime(l.created_at)}
                {l.expires_at ? `, expires ${formatDateTime(l.expires_at)}` : ', never expires'}
              </span>
              {l.status === 'active' ? (
                <button
                  className="btn btn-small btn-ghost"
                  type="button"
                  disabled={revoke.isPending}
                  onClick={() => {
                    revoke.mutate({ id: panel.id, link: l.id });
                  }}
                >
                  Revoke
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {del.isError || revoke.isError ? (
        <p className="error" role="alert">
          {(del.error ?? revoke.error)?.message}
        </p>
      ) : null}
      {deleting ? (
        <ConfirmDialog
          title={`Delete ${panel.name}`}
          actionClass="safe"
          confirmLabel="Delete panel"
          pendingLabel="Deleting…"
          pending={del.isPending}
          error={del.isError ? del.error.message : undefined}
          onConfirm={() => {
            del.mutate(panel.id);
          }}
          onClose={() => {
            setDeleting(false);
          }}
        >
          The panel and every share link to it stop working at once
          {active.length > 0 ? ` (${String(active.length)} active)` : ''}. The devices on it are not touched.
        </ConfirmDialog>
      ) : null}
    </section>
  );
}

function PanelEditor({ panel, devices, onClose }: { panel?: Panel; devices: Device[]; onClose: () => void }) {
  const save = useSavePanel();
  const [draft, setDraft] = useState<PanelInput>(() => (panel ? toInput(panel) : { name: '', widgets: [] }));
  const [pick, setPick] = useState('');
  const byId = new Map(devices.map((d) => [d.id, d]));
  const available = devices.filter((d) => !draft.widgets.some((w) => w.entity === d.id));

  return (
    <Modal className="dialog dialog-wide" labelledBy="panel-editor-title" onClose={onClose}>
      <h2 id="panel-editor-title">{panel ? `Edit ${panel.name}` : 'New panel'}</h2>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ id: panel?.id, panel: draft }, { onSuccess: onClose });
        }}
      >
        <label className="field">
          Name
          <input
            value={draft.name}
            maxLength={100}
            required
            placeholder="Living room"
            onChange={(e) => {
              setDraft({ ...draft, name: e.target.value });
            }}
          />
        </label>

        <div className="panel-editor-widgets">
          {draft.widgets.length === 0 ? <p className="muted small">Add the devices this panel shows.</p> : null}
          {draft.widgets.map((w, i) => {
            const d = byId.get(w.entity);
            const services = restartServices(d);
            return (
              <div key={w.entity} className="panel-editor-widget">
                <div className="panel-editor-widget-head">
                  <StatusDot status={d?.status ?? 'unknown'} />
                  <strong>{d ? displayName(d) : w.entity}</strong>
                  <div className="row-actions">
                    <button
                      className="btn btn-small btn-ghost"
                      type="button"
                      aria-label="Move up"
                      disabled={i === 0}
                      onClick={() => {
                        setDraft(moveWidget(draft, i, -1));
                      }}
                    >
                      ↑
                    </button>
                    <button
                      className="btn btn-small btn-ghost"
                      type="button"
                      aria-label="Move down"
                      disabled={i === draft.widgets.length - 1}
                      onClick={() => {
                        setDraft(moveWidget(draft, i, 1));
                      }}
                    >
                      ↓
                    </button>
                    <button
                      className="btn btn-small btn-ghost"
                      type="button"
                      onClick={() => {
                        setDraft(moveWidget(draft, i, 0));
                      }}
                    >
                      Remove
                    </button>
                  </div>
                </div>
                {services.length === 0 ? (
                  <p className="muted small">
                    Shown read-only: this device&apos;s agent allows no restarts (start it with{' '}
                    <code>--allow-restart</code>).
                  </p>
                ) : (
                  <fieldset className="panel-editor-actions">
                    <legend className="small muted">Guests may restart</legend>
                    {services.map((s) => (
                      <label key={s} className="check">
                        <input
                          type="checkbox"
                          checked={w.actions.some((a) => a.action === 'device.restart' && a.service === s)}
                          onChange={(e) => {
                            setDraft(toggleRestart(draft, i, s, e.target.checked));
                          }}
                        />
                        <span className="mono">{s}</span>
                      </label>
                    ))}
                  </fieldset>
                )}
              </div>
            );
          })}
        </div>

        <div className="panel-editor-add">
          <label className="field">
            Add a device
            <select
              value={pick}
              onChange={(e) => {
                setPick(e.target.value);
              }}
            >
              <option value="">Choose a device…</option>
              {available.map((d) => (
                <option key={d.id} value={d.id}>
                  {displayName(d)}
                </option>
              ))}
            </select>
          </label>
          <button
            className="btn"
            type="button"
            disabled={pick === ''}
            onClick={() => {
              setDraft(addDevice(draft, pick));
              setPick('');
            }}
          >
            Add
          </button>
        </div>

        <p className="muted small">
          Only restarts can be offered, never anything dangerous. Each one a guest takes is decided by the hub&apos;s
          policy (the <code>guest</code> actor) and audited.
        </p>
        {save.isError ? (
          <p className="error" role="alert">
            {save.error.message}
          </p>
        ) : null}
        <div className="form-actions">
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" disabled={save.isPending}>
            {save.isPending ? 'Saving…' : 'Save panel'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ShareDialog({ panel, onClose }: { panel: Panel; onClose: () => void }) {
  const create = useCreatePanelLink();
  const [expiresIn, setExpiresIn] = useState('');
  const [created, setCreated] = useState<CreatedPanelLink | null>(null);
  const origin = useShareOrigin();

  return (
    <Modal className="dialog" labelledBy="share-panel-title" onClose={onClose}>
      <h2 id="share-panel-title">Share {panel.name}</h2>
      {created ? (
        <>
          <div className="notice" role="status">
            <strong>Copy the link now: it is shown only this once.</strong>
            <span>Anyone with it can see this panel and take the restarts it allows. Revoke it when done.</span>
          </div>
          {origin ? (
            <>
              <Command label="Guest link" value={shareURL(origin, created.path, false)} />
              <Command label="Kiosk link (full screen, for a wall display)" value={shareURL(origin, created.path, true)} />
            </>
          ) : null}
          <div className="form-actions">
            <button className="btn btn-primary" type="button" onClick={onClose}>
              Done
            </button>
          </div>
        </>
      ) : (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({ id: panel.id, expiresIn }, { onSuccess: setCreated });
          }}
        >
          <label className="field">
            Link lasts
            <select
              value={expiresIn}
              onChange={(e) => {
                setExpiresIn(e.target.value);
              }}
            >
              {linkExpiries.map((x) => (
                <option key={x.value} value={x.value}>
                  {x.label}
                </option>
              ))}
            </select>
          </label>
          {create.isError ? (
            <p className="error" role="alert">
              {create.error.message}
            </p>
          ) : null}
          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={create.isPending}>
              Create link
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
