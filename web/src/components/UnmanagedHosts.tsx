import { useState } from 'react';
import type { NetworkHost, NetworkHostSource } from '../api/client.ts';
import { useAdoptNetworkHost, useDevices, useMarkNetworkHost, useNetworkHosts } from '../api/hooks.ts';
import { adoptPrefill, hostName, maxAdoptName, validAdoptName } from '../adopt.ts';
import { relativeTime } from '../format.ts';
import { hostKinds, hostKindTitle } from '../hostkinds.ts';

/** A MAC whose locally administered bit is set: a randomized ("private") address. */
function isRandomized(mac: string) {
  return (parseInt(mac.slice(0, 2), 16) & 0x02) !== 0;
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

/** The inline prompt for the name a host is adopted under, prefilled with its name. */
function AdoptForm({ host, onDone }: { host: NetworkHost; onDone: () => void }) {
  const adopt = useAdoptNetworkHost();
  const [name, setName] = useState(() => adoptPrefill(host));
  return (
    <form
      className="adopt-form"
      onSubmit={(e) => {
        e.preventDefault();
        adopt.mutate({ mac: host.mac, name: name.trim() }, { onSuccess: onDone });
      }}
    >
      <input
        aria-label={`Name for ${hostName(host)}`}
        value={name}
        maxLength={maxAdoptName}
        autoFocus
        aria-invalid={adopt.isError || undefined}
        onChange={(e) => {
          setName(e.target.value);
        }}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            onDone();
          }
        }}
      />
      <button className="btn btn-small" type="submit" disabled={adopt.isPending || !validAdoptName(name)}>
        Adopt
      </button>
      <button className="btn btn-ghost btn-small" type="button" onClick={onDone}>
        Cancel
      </button>
      {adopt.error ? (
        <span className="error" role="alert">
          {adopt.error.message}
        </span>
      ) : null}
    </form>
  );
}

/**
 * Hosts network discovery found that have no agent, each with a shortcut to
 * the "Add device" flow and to adopting it as a device without an agent.
 * Adopted hosts are listed under Network devices instead. Renders nothing
 * while discovery has found none.
 */
export function UnmanagedHosts({ now, onAdd }: { now: number; onAdd: (h: NetworkHost) => void }) {
  const hosts = useNetworkHosts();
  const devices = useDevices();
  const mark = useMarkNetworkHost();
  /** The MAC of the host whose adopt prompt is open. */
  const [adopting, setAdopting] = useState<string | null>(null);
  /** The name of the device a scan ran from: hosts on a subnet only that device is on. */
  const scannerName = (id: string) => devices.data?.find((d) => d.id === id)?.name ?? id;
  const list = (hosts.data ?? []).filter((h) => h.device_id === '' && h.state !== 'adopted').sort(byIP);
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
                  <span className="host-kind muted" title={hostKindTitle(h)}>
                    <svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true">
                      <path d={hostKinds[h.kind].path} />
                    </svg>
                    {hostKinds[h.kind].label}
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
                  {h.scanned_by ? (
                    <span
                      className="scanned-by muted"
                      title={`Found by the ARP sweep from ${scannerName(h.scanned_by)}'s agent`}
                    >
                      Scanned by {scannerName(h.scanned_by)}
                    </span>
                  ) : null}
                </td>
                <td className="row-end">
                  {adopting === h.mac ? (
                    <AdoptForm
                      host={h}
                      onDone={() => {
                        setAdopting(null);
                      }}
                    />
                  ) : (
                    <span className="host-actions">
                      <button
                        className="btn btn-ghost btn-small"
                        type="button"
                        title="List it with your devices, without an agent: online while scans find it"
                        onClick={() => {
                          setAdopting(h.mac);
                        }}
                      >
                        Adopt
                      </button>
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
                      <button
                        className="btn btn-ghost btn-small"
                        type="button"
                        onClick={() => {
                          onAdd(h);
                        }}
                      >
                        Add device
                      </button>
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
