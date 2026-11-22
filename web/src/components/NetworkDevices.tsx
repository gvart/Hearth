import { useAdoptNetworkHost, useNetworkHosts } from '../api/hooks.ts';
import { adoptedHosts } from '../adopt.ts';
import { relativeTime } from '../format.ts';
import { hostKinds, hostKindTitle } from '../hostkinds.ts';

/**
 * Hosts without an agent the operator adopted as devices (a printer, a TV, a
 * router): online while scans find them, with no control actions. Renders
 * nothing while none is adopted.
 */
export function NetworkDevices({ now }: { now: number }) {
  const hosts = useNetworkHosts();
  const adopt = useAdoptNetworkHost();
  const list = adoptedHosts(hosts.data ?? []);
  if (list.length === 0) {
    return null;
  }
  return (
    <section className="network-devices" aria-labelledby="network-devices-title">
      <div className="section-head">
        <h2 id="network-devices-title">Network devices</h2>
        <p className="muted">
          {list.length === 1 ? '1 device' : `${String(list.length)} devices`} without an agent, online while network
          discovery finds them
        </p>
      </div>
      <div className="table-wrap">
        <table className="devices network">
          <thead>
            <tr>
              <th>Name</th>
              <th>Vendor</th>
              <th>IP</th>
              <th>Last seen</th>
              <th>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {list.map((h) => {
              const status = h.online ? 'Online' : 'Offline';
              return (
                <tr key={h.mac} aria-label={`${h.name}, ${status.toLowerCase()}`}>
                  <td>
                    <span className="name-cell">
                      <span
                        className={`dot ${h.online ? 'dot-online' : 'dot-offline'}`}
                        role="img"
                        aria-label={status}
                        title={h.online ? 'Online: a recent scan found it' : 'Offline: no recent scan found it'}
                      />
                      <span className="name">{h.name}</span>
                    </span>
                    <span className="host-kind muted" title={hostKindTitle(h)}>
                      <svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true">
                        <path d={hostKinds[h.kind].path} />
                      </svg>
                      {hostKinds[h.kind].label}
                    </span>
                  </td>
                  <td className="muted" title={h.vendor}>
                    {h.vendor || '—'}
                  </td>
                  <td className="mono">{h.ip}</td>
                  <td className="muted">{relativeTime(h.last_seen, now)}</td>
                  <td className="row-end">
                    <button
                      className="btn btn-ghost btn-small"
                      type="button"
                      disabled={adopt.isPending}
                      title="Back to On your network, without its name"
                      onClick={() => {
                        adopt.mutate({ mac: h.mac, name: null });
                      }}
                    >
                      Unadopt
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
