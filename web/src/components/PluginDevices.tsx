import { useState } from 'react';
import {
  usePlugins,
  type Plugin,
  type PluginCommandSpec,
  type PluginDevice,
  type PluginEntity,
  type PluginState,
  type PolicyDecision,
} from '../api/plugins.ts';
import { PluginCommandDialog } from './PluginCommandDialog.tsx';
import './PluginDevices.css';

const stateLabels: Record<PluginState, string> = {
  running: 'Running',
  starting: 'Starting',
  restarting: 'Restarting',
  stopped: 'Stopped',
};

function stateDot(s: PluginState) {
  if (s === 'running') {
    return 'dot dot-online';
  }
  return s === 'stopped' ? 'dot dot-offline' : 'dot dot-unknown';
}

/** An entity's state as text: "on"/"off" for a switch, the value and unit otherwise. */
function stateText(e: PluginEntity) {
  const v = e.state;
  if (v === null || v === undefined) {
    return '—';
  }
  if (typeof v === 'boolean') {
    return e.kind === 'switch' || e.kind === undefined ? (v ? 'on' : 'off') : String(v);
  }
  const text = typeof v === 'string' ? v : JSON.stringify(v);
  return e.unit ? `${text} ${e.unit}` : text;
}

/** A row of the table: a plugin's device, or the plugin itself when it reports none. */
interface Row {
  plugin: Plugin;
  device?: PluginDevice;
}

interface Picked {
  plugin: Plugin;
  device?: PluginDevice;
  command: PluginCommandSpec;
}

/**
 * The devices and entities the hub's exec plugins report, with the commands
 * each plugin declares. Renders nothing when the hub runs no plugins.
 */
export function PluginDevices() {
  const q = usePlugins();
  const [picked, setPicked] = useState<Picked>();
  const data = q.data;
  if (q.isError) {
    return (
      <section className="unmanaged" aria-labelledby="plugins-title">
        <div className="section-head">
          <h2 id="plugins-title">From plugins</h2>
        </div>
        <div className="error-box" role="alert">
          Could not load plugins: {q.error.message}
        </div>
      </section>
    );
  }
  if (!data || data.plugins.length === 0) {
    return null;
  }
  const rows: Row[] = data.plugins.flatMap((p) =>
    p.devices.length > 0 ? p.devices.map((d) => ({ plugin: p, device: d })) : [{ plugin: p }],
  );
  const devices = data.plugins.reduce((n, p) => n + p.devices.length, 0);
  const decisionOf = (c: PluginCommandSpec): PolicyDecision => data.decisions[c.class];

  return (
    <section className="unmanaged" aria-labelledby="plugins-title">
      <div className="section-head">
        <h2 id="plugins-title">From plugins</h2>
        <p className="muted">
          {String(devices)} {devices === 1 ? 'device' : 'devices'} from {String(data.plugins.length)}{' '}
          {data.plugins.length === 1 ? 'plugin' : 'plugins'}
        </p>
      </div>
      {data.plugins
        .filter((p) => p.state !== 'running' && p.error)
        .map((p) => (
          <div key={p.name} className="error-box" role="alert">
            Plugin {p.name} is {p.state}: {p.error}
          </div>
        ))}
      <div className="table-wrap">
        <table className="devices network plugin-devices">
          <thead>
            <tr>
              <th>Name</th>
              <th>Plugin</th>
              <th>State</th>
              <th>Commands</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ plugin, device }) => (
              <tr
                key={`${plugin.name}/${device?.id ?? ''}`}
                aria-label={`${device ? device.name || device.id : plugin.name}, plugin ${stateLabels[plugin.state]}`}
              >
                <td>
                  <span className="name-cell">
                    <span
                      className={stateDot(plugin.state)}
                      role="img"
                      aria-label={stateLabels[plugin.state]}
                      title={`Plugin ${stateLabels[plugin.state].toLowerCase()}`}
                    />
                    {device ? (
                      <>
                        <span className="name">{device.name || device.id}</span>
                        {device.kind ? <span className="badge badge-quiet">{device.kind}</span> : null}
                      </>
                    ) : (
                      <span className="muted">No devices reported</span>
                    )}
                  </span>
                </td>
                <td>
                  <span className="mono">{plugin.name}</span> <span className="muted small">{plugin.version}</span>
                </td>
                <td>
                  {device && device.entities.length > 0 ? (
                    <span className="chips">
                      {device.entities.map((e) => (
                        <span key={e.id} className="chip" title={e.id}>
                          {e.name || e.id}: {stateText(e)}
                        </span>
                      ))}
                    </span>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td>
                  {plugin.commands.length > 0 ? (
                    <span className="plugin-commands">
                      {plugin.commands.map((c) => {
                        const decision = decisionOf(c);
                        const title =
                          decision === 'deny'
                            ? `Policy denies ${c.class} plugin commands`
                            : `${c.description ?? c.name} (${c.class}${decision === 'confirm' ? ', needs approval' : ''})`;
                        return (
                          <button
                            key={c.name}
                            className={`btn btn-ghost btn-small${c.class === 'dangerous' ? ' btn-danger-ghost' : ''}`}
                            type="button"
                            title={title}
                            aria-label={`${c.name}: ${title}`}
                            disabled={decision === 'deny'}
                            onClick={() => {
                              setPicked({ plugin, device, command: c });
                            }}
                          >
                            {c.name}
                            {decision === 'confirm' ? <span className="badge badge-quiet">approval</span> : null}
                            {decision === 'deny' ? <span className="badge badge-quiet">denied</span> : null}
                          </button>
                        );
                      })}
                    </span>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {picked ? (
        <PluginCommandDialog
          plugin={picked.plugin}
          device={picked.device}
          command={picked.command}
          decision={decisionOf(picked.command)}
          onClose={() => {
            setPicked(undefined);
          }}
        />
      ) : null}
    </section>
  );
}
