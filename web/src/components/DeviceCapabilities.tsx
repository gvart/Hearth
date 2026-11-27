import { useState } from 'react';
import { useCapabilities, useSetCapabilities } from '../api/capabilities.ts';
import { ApiError, type Ceiling, type Device, type PluginGrant } from '../api/client.ts';
import { useDevicePluginRegistry } from '../api/deviceplugins.ts';
import {
  applied,
  capStates,
  cardMode,
  emptyCeiling,
  isAll,
  newRelease,
  parseList,
  pluginClasses,
  withoutPlugin,
  withPlugin,
  withPluginRelease,
  withDocker,
  withList,
  withSwitch,
  type Capabilities,
  type CapState,
  type DockerLevel,
  type PluginRelease,
} from '../capabilities.ts';
import { formatDateTime } from '../format.ts';
import { AgentVersionLink } from './DeviceUpgrade.tsx';
import { Tip } from './Tip.tsx';
import './DeviceCapabilities.css';

/** The card's anchor: the hints elsewhere on the page link here. */
export const capabilitiesAnchor = 'capabilities';

/** Scrolls to the Capabilities card of the device page, for a hint that something is off there. */
export function CapabilitiesLink({ children }: { children: string }) {
  return (
    <button
      type="button"
      className="link"
      onClick={() => {
        document.getElementById(capabilitiesAnchor)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }}
    >
      {children}
    </button>
  );
}

/**
 * What the hub may do on the device (#346), each switched on or off here and
 * applied by its agent at once. What a flag on the device grants shows as set
 * there: the hub cannot take it away. An agent started with --local-ceiling,
 * or too old to take capabilities from the hub, is shown read-only.
 */
export function DeviceCapabilities({ device }: { device: Device }) {
  const q = useCapabilities(device.id, device.status === 'online');
  const caps = q.data;
  const isApplying = caps !== undefined && device.status === 'online' && !applied(caps);
  return (
    <section className="panel-card card-wide caps-card" id={capabilitiesAnchor} aria-label="Capabilities">
      <div className="panel-card-head">
        <h2 className="card-label">
          Capabilities <Tip id="capabilities" />
        </h2>
        {caps ? <ModePill caps={caps} /> : null}
      </div>
      {q.isError ? (
        <div className="error-box" role="alert">
          Could not load the device&apos;s capabilities: {q.error.message}
        </div>
      ) : !caps ? (
        <p className="muted small">Loading…</p>
      ) : (
        <CapsBody device={device} caps={caps} applying={isApplying} />
      )}
    </section>
  );
}

function ModePill({ caps }: { caps: Capabilities }) {
  switch (cardMode(caps)) {
    case 'locked':
      return <span className="pill pill-muted">set on the device</span>;
    case 'upgrade':
      return <span className="pill pill-warn">agent too old</span>;
    case 'unreported':
      return <span className="pill pill-muted">not reported yet</span>;
  }
  return null;
}

function CapsBody({ device, caps, applying }: { device: Device; caps: Capabilities; applying: boolean }) {
  const set = useSetCapabilities(device.id);
  const [editing, setEditing] = useState<string>();
  const mode = cardMode(caps);
  const readOnly = mode === 'locked' || mode === 'upgrade';
  const hub = { ...emptyCeiling(), ...caps.hub };
  const change = (to: Ceiling) => {
    set.mutate({ from: hub, to });
  };
  const states = capStates(caps, device.os);
  return (
    <>
      {mode === 'locked' ? (
        <p className="muted small caps-note">
          This device&apos;s agent runs with <code>--local-ceiling</code>: what the hub may do there is set on the
          device, with its <code>--allow-*</code> flags. Shown here as it is, read-only.
        </p>
      ) : mode === 'upgrade' ? (
        <div className="notice small caps-upgrade">
          <span>
            Upgrade the agent to manage capabilities from here
            {caps.agent_version ? (
              <>
                {' '}
                (it runs <span className="mono">{caps.agent_version}</span>)
              </>
            ) : null}
            . Until then they are what it was started with, shown here as they are.
          </span>
          {device.agent_version?.upgrade_available ? <AgentVersionLink>Upgrade agent</AgentVersionLink> : null}
        </div>
      ) : null}
      <ul className="caps-list">
        {states.map((s) => (
          <CapRow
            key={s.info.key}
            s={s}
            hub={hub}
            readOnly={readOnly}
            effective={caps.effective}
            busy={set.isPending}
            editing={editing === s.info.key}
            onEdit={(on) => {
              setEditing(on ? s.info.key : undefined);
            }}
            onChange={(to) => {
              setEditing(undefined);
              change(to);
            }}
          />
        ))}
      </ul>
      <PluginsSection
        grants={hub.plugins ?? []}
        local={caps.local?.plugins ?? []}
        effective={caps.effective?.plugins ?? []}
        reported={caps.effective !== null}
        manageable={caps.plugins_manageable}
        readOnly={mode === 'locked' || mode === 'upgrade' || !caps.plugins_manageable}
        busy={set.isPending}
        releases={caps.plugin_releases}
        windows={device.os.toLowerCase().includes('windows')}
        onAdd={(name, cls) => {
          change(withPlugin(hub, name, cls));
        }}
        onApprove={(name, digest) => {
          change(withPluginRelease(hub, name, digest));
        }}
        onRemove={(name) => {
          change(withoutPlugin(hub, name));
        }}
      />
      {set.isError && !(set.error instanceof ApiError && set.error.code === 'reauth_cancelled') ? (
        <div className="error-box" role="alert">
          {set.error instanceof ApiError && set.error.code === 'forbidden'
            ? 'Denied by policy.'
            : set.error.message}
        </div>
      ) : null}
      <p className="muted small caps-foot" role="status">
        {mode === 'managed' || mode === 'unreported'
          ? applying
            ? 'Applying on the device…'
            : device.status !== 'online'
              ? 'Changes apply when the device is back online.'
              : 'Applied by the agent at once, no restart.'
          : null}
        {caps.updated_at ? (
          <>
            {' '}
            Last changed {formatDateTime(caps.updated_at)}
            {caps.updated_by ? <> by {caps.updated_by}</> : null}.
          </>
        ) : null}
      </p>
    </>
  );
}

interface RowProps {
  s: CapState;
  hub: Ceiling;
  readOnly: boolean;
  effective: Ceiling | null;
  busy: boolean;
  editing: boolean;
  onEdit: (on: boolean) => void;
  onChange: (to: Ceiling) => void;
}

function CapRow({ s, hub, readOnly, effective, busy, editing, onEdit, onChange }: RowProps) {
  const { info } = s;
  const disabled = readOnly || busy || s.unsupported !== undefined;
  return (
    <li className="caps-row">
      <div className="caps-what">
        <span className="caps-name">
          {info.label}
          {info.risky ? (
            <span className="caps-risk small" title="Turning it on asks for your password again">
              dangerous
            </span>
          ) : null}
        </span>
        <span className="muted small">{info.what}</span>
        {s.local ? (
          <span className="caps-local small">
            Set on the device{s.localList.length ? <>: <span className="mono">{listText(info.key, s.localList)}</span></> : null}
          </span>
        ) : null}
        {s.unsupported ? <span className="muted small">{s.unsupported}</span> : null}
      </div>
      <div className="caps-control">
        {readOnly ? (
          <ReadOnlyValue s={s} effective={effective} />
        ) : info.kind === 'docker' ? (
          <DockerLevels
            value={s.docker.hub}
            floor={s.docker.local}
            disabled={disabled}
            onChange={(level) => {
              onChange(withDocker(hub, level));
            }}
          />
        ) : info.kind === 'exec' ? (
          <ListValue s={s} disabled={disabled} onEdit={onEdit} onClear={() => { onChange(withList(hub, 'exec', [])); }} />
        ) : (
          <>
            <Switch
              label={info.label}
              on={s.hubOn || s.local}
              locked={s.local && (info.kind === 'switch' || !s.hubOn)}
              disabled={disabled || (s.local && info.kind === 'switch')}
              onToggle={() => {
                onChange(withSwitch(hub, info.key, !s.hubOn));
              }}
            />
            {info.kind === 'list' ? <ListValue s={s} disabled={disabled} onEdit={onEdit} /> : null}
          </>
        )}
      </div>
      {editing ? (
        <ListEditor
          s={s}
          onCancel={() => {
            onEdit(false);
          }}
          onSave={(list) => {
            onChange(withList(hub, info.key, list));
          }}
        />
      ) : null}
    </li>
  );
}

function listText(key: CapState['info']['key'], list: string[]): string {
  return isAll(key, list) ? 'all' : list.join(', ');
}

/** The hub's list of a list capability, and the way to restrict or edit it. */
function ListValue({
  s,
  disabled,
  onEdit,
  onClear,
}: {
  s: CapState;
  disabled: boolean;
  onEdit: (on: boolean) => void;
  onClear?: () => void;
}) {
  const { info } = s;
  const all = isAll(info.key, s.hubList);
  const restrict = info.kind === 'exec' ? (s.hubList.length ? 'Edit' : 'Add programs…') : s.hubOn && !all ? 'Edit' : 'Restrict to…';
  return (
    <div className="caps-list-value">
      {s.hubList.length && !all ? <span className="mono small caps-entries">{s.hubList.join(', ')}</span> : null}
      {info.kind === 'exec' && !s.hubList.length ? <span className="muted small">none</span> : null}
      <button
        type="button"
        className="link small"
        disabled={disabled}
        onClick={() => {
          onEdit(true);
        }}
      >
        {restrict}
      </button>
      {onClear && s.hubList.length ? (
        <button type="button" className="link small" disabled={disabled} onClick={onClear}>
          Turn off
        </button>
      ) : null}
    </div>
  );
}

function ListEditor({ s, onCancel, onSave }: { s: CapState; onCancel: () => void; onSave: (list: string[]) => void }) {
  const { info } = s;
  const start = isAll(info.key, s.hubList) ? [] : s.hubList;
  const [text, setText] = useState(start.join(', '));
  const id = `caps-edit-${info.key}`;
  return (
    <form
      className="caps-editor"
      onSubmit={(e) => {
        e.preventDefault();
        onSave(parseList(text));
      }}
    >
      <label htmlFor={id} className="small">
        {info.kind === 'exec'
          ? 'Programs the hub may run, as absolute paths, comma-separated. Each runs with any arguments.'
          : `Only these, comma-separated${info.key === 'scan' ? ' (IPv4 subnets)' : ' (manager:name; a name may be a glob such as docker:*)'}.`}
      </label>
      <input
        id={id}
        className="mono"
        value={text}
        placeholder={info.placeholder}
        autoFocus
        onChange={(e) => {
          setText(e.target.value);
        }}
      />
      <div className="form-actions">
        <button type="button" className="btn btn-ghost btn-small" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="btn btn-primary btn-small">
          Save
        </button>
      </div>
    </form>
  );
}

function Switch({
  label,
  on,
  locked,
  disabled,
  onToggle,
}: {
  label: string;
  on: boolean;
  locked: boolean;
  disabled: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      className={`caps-switch${on ? ' is-on' : ''}${locked ? ' is-locked' : ''}`}
      disabled={disabled}
      onClick={onToggle}
    >
      <span className="caps-switch-off">Off</span>
      <span className="caps-switch-on">On</span>
    </button>
  );
}

const levels: { level: DockerLevel; label: string }[] = [
  { level: 'off', label: 'Off' },
  { level: 'read', label: 'Read' },
  { level: 'control', label: 'Control' },
];

/** Docker's three levels; those below what the device's flags grant cannot be picked. */
function DockerLevels({
  value,
  floor,
  disabled,
  onChange,
}: {
  value: DockerLevel;
  floor: DockerLevel;
  disabled: boolean;
  onChange: (level: DockerLevel) => void;
}) {
  const rank = (l: DockerLevel) => levels.findIndex((x) => x.level === l);
  const shown = rank(value) >= rank(floor) ? value : floor;
  return (
    <div className="caps-levels" role="radiogroup" aria-label="Containers">
      {levels.map((l) => (
        <button
          key={l.level}
          type="button"
          role="radio"
          aria-checked={shown === l.level}
          className={shown === l.level ? 'is-on' : ''}
          disabled={disabled || rank(l.level) < rank(floor)}
          title={l.level === 'control' ? 'Start, stop and restart too: asks for your password' : undefined}
          onClick={() => {
            onChange(l.level);
          }}
        >
          {l.label}
        </button>
      ))}
    </div>
  );
}

/** What is in effect, for an agent the hub does not manage. */
function ReadOnlyValue({ s, effective }: { s: CapState; effective: Ceiling | null }) {
  if (s.info.kind === 'docker') {
    const level = effective?.docker ? 'control' : effective?.docker_read ? 'read' : 'off';
    return <span className={`caps-value${level === 'off' ? ' muted' : ''}`}>{level}</span>;
  }
  if (!s.effectiveOn) {
    return <span className="caps-value muted">off</span>;
  }
  const list = s.info.kind === 'switch' ? [] : listOfEffective(s, effective);
  return <span className="caps-value mono small">{list.length ? listText(s.info.key, list) : 'on'}</span>;
}

function listOfEffective(s: CapState, c: Ceiling | null): string[] {
  switch (s.info.key) {
    case 'logs':
      return c?.logs ?? [];
    case 'restart':
      return c?.restart ?? [];
    case 'scan':
      return c?.scan ?? [];
    case 'exec':
      return c?.exec ?? [];
    default:
      return [];
  }
}

const classNote = 'Adding a plugin or raising its class asks for your password again';

function grantText(g: PluginGrant[]): string {
  return g.map((x) => `${x.name} (${x.class}${x.digest ? ` @${x.digest.slice(0, 12)}` : ''})`).join(', ');
}

/** A plugin's class, as a segmented control like Containers'. */
function ClassLevels({
  label,
  value,
  disabled,
  onChange,
}: {
  label: string;
  value: PluginGrant['class'];
  disabled: boolean;
  onChange: (cls: PluginGrant['class']) => void;
}) {
  return (
    <div className="caps-levels" role="radiogroup" aria-label={label}>
      {pluginClasses.map((c) => (
        <button
          key={c}
          type="button"
          role="radio"
          aria-checked={value === c}
          className={value === c ? 'is-on' : ''}
          disabled={disabled}
          title={c === 'read' ? undefined : `Up to ${c} commands: raising it asks for your password`}
          onClick={() => {
            if (c !== value) {
              onChange(c);
            }
          }}
        >
          {c.charAt(0).toUpperCase() + c.slice(1)}
        </button>
      ))}
    </div>
  );
}

/**
 * The device plugins the hub may run commands of there, each up to a class.
 * Granting one, or raising its class, is dangerous: the password again.
 */
function PluginsSection({
  grants,
  local,
  effective,
  reported,
  manageable,
  readOnly,
  busy,
  releases,
  windows,
  onAdd,
  onApprove,
  onRemove,
}: {
  grants: PluginGrant[];
  local: PluginGrant[];
  effective: PluginGrant[];
  reported: boolean;
  manageable: boolean;
  readOnly: boolean;
  busy: boolean;
  releases: PluginRelease[];
  windows: boolean;
  onAdd: (name: string, cls: PluginGrant['class']) => void;
  onApprove: (name: string, digest: string) => void;
  onRemove: (name: string) => void;
}) {
  const registry = useDevicePluginRegistry();
  const [name, setName] = useState('');
  const [cls, setCls] = useState<PluginGrant['class']>('read');
  const disabled = readOnly || busy;
  // Uploaded plugins not granted yet: one click picks the name.
  const known = [...new Set((registry.data?.plugins ?? []).map((p) => p.name))].filter(
    (n) => !grants.some((g) => g.name === n),
  );
  return (
    <div className="caps-plugins">
      <div className="caps-what">
        <span className="caps-name">
          Plugins
          <span className="caps-risk small" title={classNote}>
            dangerous
          </span>
        </span>
        <span className="muted small">
          Run the commands of device plugins, up to the class set for each.
        </span>
        <span className="muted small">
          Any plugin runs code you upload as the agent&apos;s user, whatever its class. Each grant pins one release.
        </span>
        {!manageable ? <span className="muted small">Plugins need an agent upgrade</span> : null}
        {windows ? <span className="muted small">Device plugins are not supported on Windows yet</span> : null}
        {local.length ? (
          <span className="caps-local small">
            Set on the device: <span className="mono">{grantText(local)}</span>
          </span>
        ) : null}
        {reported ? (
          <span className="muted small">
            In effect: <span className="mono">{effective.length ? grantText(effective) : 'none'}</span>
          </span>
        ) : null}
      </div>
      {grants.length ? (
        <ul className="caps-list">
          {grants.map((g) => {
            const pinned = releases.find((r) => r.digest === g.digest);
            const next = newRelease(g, releases);
            return (
              <li key={g.name} className="caps-row">
                <span className="caps-what">
                  <span className="caps-name mono">{g.name}</span>
                  <span className="muted small mono" title={g.digest}>
                    {pinned ? `v${pinned.version} · ` : ''}
                    {g.digest ? `@${g.digest.slice(0, 12)}` : ''}
                  </span>
                  {next ? (
                    <span className="caps-plugin-update small">
                      New release v{next.version} available{' '}
                      <button
                        type="button"
                        className="link small"
                        disabled={disabled}
                        title="Moving the device to another release asks for your password again"
                        onClick={() => {
                          onApprove(g.name, next.digest);
                        }}
                      >
                        Approve
                      </button>
                    </span>
                  ) : null}
                </span>
                <div className="caps-control">
                  <ClassLevels
                    label={`Class of ${g.name}`}
                    value={g.class}
                    disabled={disabled}
                    onChange={(c) => {
                      onAdd(g.name, c);
                    }}
                  />
                  <button
                    type="button"
                    className="link small"
                    disabled={disabled}
                    onClick={() => {
                      onRemove(g.name);
                    }}
                  >
                    Remove
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      ) : null}
      {readOnly ? null : (
        <form
          className="caps-plugin-add"
          onSubmit={(e) => {
            e.preventDefault();
            const n = name.trim();
            if (n) {
              onAdd(n, cls);
              setName('');
            }
          }}
        >
          <input
            className="mono"
            aria-label="Plugin name"
            value={name}
            placeholder="plugin name"
            autoComplete="off"
            disabled={busy}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
          <ClassLevels label="Class of the new plugin" value={cls} disabled={busy} onChange={setCls} />
          <button type="submit" className="btn btn-primary btn-small" disabled={busy || name.trim() === ''} title={classNote}>
            Add plugin
          </button>
          {known.length ? (
            <span className="muted small caps-plugin-known">
              Uploaded:{' '}
              {known.map((n) => (
                <button
                  key={n}
                  type="button"
                  className="link small mono"
                  disabled={busy}
                  onClick={() => {
                    setName(n);
                  }}
                >
                  {n}
                </button>
              ))}
            </span>
          ) : null}
        </form>
      )}
    </div>
  );
}
