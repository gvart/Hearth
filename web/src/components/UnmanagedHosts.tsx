import type { NetworkHost } from '../api/client.ts';
import { useNetworkHosts } from '../api/hooks.ts';
import { relativeTime } from '../format.ts';

/** A MAC whose locally administered bit is set: a randomized ("private") address. */
function isRandomized(mac: string) {
  return (parseInt(mac.slice(0, 2), 16) & 0x02) !== 0;
}

function hostName(h: NetworkHost) {
  return h.hostname.replace(/\.local$/, '') || h.vendor || h.ip;
}

function vendorLabel(h: NetworkHost) {
  if (h.vendor) {
    return h.vendor;
  }
  return isRandomized(h.mac) ? 'Private address' : '—';
}

function byIP(a: NetworkHost, b: NetworkHost) {
  const n = (ip: string) => ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);
  return n(a.ip) - n(b.ip);
}

/**
 * Hosts network discovery found that have no agent, each with a shortcut to
 * the "Add device" flow. Renders nothing while discovery has found none.
 */
export function UnmanagedHosts({ now, onAdd }: { now: number; onAdd: () => void }) {
  const hosts = useNetworkHosts();
  const list = (hosts.data ?? []).filter((h) => h.device_id === '').sort(byIP);
  if (list.length === 0) {
    return null;
  }
  return (
    <section className="unmanaged" aria-labelledby="unmanaged-title">
      <div className="section-head">
        <h2 id="unmanaged-title">On your network</h2>
        <p className="muted">
          {list.length === 1 ? '1 unmanaged host' : `${String(list.length)} unmanaged hosts`} found by network
          discovery
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
              <th>MAC</th>
              <th>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {list.map((h) => (
              <tr key={h.mac} aria-label={`${hostName(h)}, unmanaged`}>
                <td>
                  <span className="name-cell">
                    <span className="dot dot-unmanaged" role="img" aria-label="Unmanaged" title="Unmanaged: no agent" />
                    <span className="name">{hostName(h)}</span>
                  </span>
                </td>
                <td className="muted">{vendorLabel(h)}</td>
                <td className="mono">{h.ip}</td>
                <td className="muted">{relativeTime(h.last_seen, now)}</td>
                <td className="mono muted">{h.mac}</td>
                <td className="row-end">
                  <button className="btn btn-ghost btn-small" type="button" onClick={onAdd}>
                    Add device
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
