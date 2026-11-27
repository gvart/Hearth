import type { Device } from "../api/client.ts";
import { useNetEdges, type Peer } from "../api/netedges.ts";
import { formatDateTime } from "../format.ts";
import { CapabilitiesLink } from "./DeviceCapabilities.tsx";
import "./DeviceNetEdges.css";

/** Who the device sees on its network and holds TCP connections with, as its agent reports. */
export function DeviceNetEdges({ device }: { device: Device }) {
  if (!device.facts.ceiling?.net_edges) {
    return (
      <p className="muted small">
        Not reported. Turn Neighbors on in{" "}
        <CapabilitiesLink>Capabilities</CapabilitiesLink> (Linux) to see its
        neighbours and connections here.
      </p>
    );
  }
  return <NetEdgesTables deviceId={device.id} />;
}

function NetEdgesTables({ deviceId }: { deviceId: string }) {
  const q = useNetEdges(deviceId);
  if (q.isPending) {
    return <p className="muted small">Loading…</p>;
  }
  if (q.isError) {
    return (
      <p className="muted small">Cannot read the edges: {q.error.message}</p>
    );
  }
  const e = q.data;
  const refresh = (
    <button
      className="btn btn-ghost"
      type="button"
      disabled={q.isFetching}
      onClick={() => {
        void q.refetch();
      }}
    >
      Refresh
    </button>
  );
  if (!e.enabled || (e.neighbors.length === 0 && e.connections.length === 0)) {
    return (
      <div className="net-edges-head">
        <p className="muted small">
          Nothing reported yet; the agent reports every minute.
        </p>
        {refresh}
      </div>
    );
  }
  return (
    <div className="net-edges">
      <div className="net-edges-head">
        <span className="muted small">
          Last changed {formatDateTime(e.updated_at)}
        </span>
        {refresh}
      </div>
      <div className="net-edges-head">
        <h4 className="small">Connections ({String(e.connections.length)})</h4>
      </div>
      {e.connections.length ? (
        <table className="mini net-edges">
          <thead>
            <tr>
              <th>Peer</th>
              <th>Direction</th>
              <th className="num">Port</th>
              <th className="num">Count</th>
            </tr>
          </thead>
          <tbody>
            {e.connections.map((c) => (
              <tr key={`${c.ip}|${String(c.port)}|${String(c.inbound)}`}>
                <td>
                  <PeerName peer={c.peer} ip={c.ip} />
                </td>
                <td
                  title={
                    c.inbound
                      ? "The peer connected to this port here"
                      : "This device connected to the peer’s port"
                  }
                >
                  {c.inbound ? "← inbound" : "→ outbound"}
                </td>
                <td className="num">
                  <span className="mono">{c.port}</span>
                  {c.service ? <span className="svc">{c.service}</span> : null}
                </td>
                <td className="num">{c.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted small">No established connections.</p>
      )}
      <div className="net-edges-head">
        <h4 className="small">Neighbors ({String(e.neighbors.length)})</h4>
      </div>
      {e.neighbors.length ? (
        <table className="mini net-edges">
          <thead>
            <tr>
              <th>Peer</th>
              <th>MAC</th>
            </tr>
          </thead>
          <tbody>
            {e.neighbors.map((n) => (
              <tr key={n.ip}>
                <td>
                  <PeerName peer={n.peer} ip={n.ip} />
                </td>
                <td className="mono">{n.mac}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted small">No neighbours.</p>
      )}
    </div>
  );
}

/** The peer's name and kind, with its address below. */
function PeerName({ peer, ip }: { peer: Peer | null; ip: string }) {
  return (
    <>
      {peer ? (
        <span className="peer">
          <span>{peer.name}</span>
          <span className="chip">{peer.kind}</span>
        </span>
      ) : (
        <span className="muted">unknown</span>
      )}
      <span className="addr">{ip}</span>
    </>
  );
}
