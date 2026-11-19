import type { NetworkHost, NetworkHostSource } from '../api/client.ts';
import { useMarkNetworkHost, useNetworkHosts } from '../api/hooks.ts';
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

const sourceLabels: Record<NetworkHostSource, { label: string; title: string }> = {
  scan: { label: 'Scan', title: 'Found by the ARP sweep' },
  pihole: { label: 'Pi-hole', title: 'Known to Pi-hole' },
  dhcp: { label: 'DHCP', title: 'In a DHCP lease file' },
  netalertx: { label: 'NetAlertX', title: 'Known to NetAlertX' },
};

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
  const mark = useMarkNetworkHost();
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
              <th>Source</th>
              <th>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {list.map((h) => (
              <tr
                key={h.mac}
                className={h.state === 'ignored' ? 'host-ignored' : undefined}
                aria-label={`${hostName(h)}, unmanaged${h.state ? `, ${h.state}` : ''}`}
              >
                <td>
                  <span className="name-cell">
                    <span className="dot dot-unmanaged" role="img" aria-label="Unmanaged" title="Unmanaged: no agent" />
                    <span className="name">{hostName(h)}</span>
                    {h.state === 'known' ? <span className="badge badge-quiet">Known</span> : null}
                    {h.state === 'ignored' ? <span className="badge badge-quiet">Ignored</span> : null}
                  </span>
                </td>
                <td className="muted" title={vendorLabel(h)}>
                  {vendorLabel(h)}
                </td>
                <td className="mono">{h.ip}</td>
                <td className="muted">{relativeTime(h.last_seen, now)}</td>
                <td className="mono muted">{h.mac}</td>
                <td>
                  <span className="chips">
                    {h.sources.map((s) => (
                      <span className="pill pill-muted" key={s} title={sourceLabels[s].title}>
                        {sourceLabels[s].label}
                      </span>
                    ))}
                  </span>
                </td>
                <td className="row-end">
                  <span className="host-actions">
                    {h.state === '' ? (
                      <>
                        <button
                          className="btn btn-ghost btn-small"
                          type="button"
                          disabled={mark.isPending}
                          title="Yours: no more new-device alerts for it"
                          onClick={() => {
                            mark.mutate({ mac: h.mac, state: 'known' });
                          }}
                        >
                          Known
                        </button>
                        <button
                          className="btn btn-ghost btn-small"
                          type="button"
                          disabled={mark.isPending}
                          title="Not worth hearing about: no more new-device alerts for it"
                          onClick={() => {
                            mark.mutate({ mac: h.mac, state: 'ignored' });
                          }}
                        >
                          Ignore
                        </button>
                      </>
                    ) : (
                      <button
                        className="btn btn-ghost btn-small"
                        type="button"
                        disabled={mark.isPending}
                        title="Alert again when it comes back after an hour away"
                        onClick={() => {
                          mark.mutate({ mac: h.mac, state: '' });
                        }}
                      >
                        Unmark
                      </button>
                    )}
                    <button className="btn btn-ghost btn-small" type="button" onClick={onAdd}>
                      Add device
                    </button>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
