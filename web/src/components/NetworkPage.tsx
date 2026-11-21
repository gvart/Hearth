import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { fit, panBy, transformOf, zoomAt, type View } from '../panzoom.ts';
import { useDevices } from '../api/hooks.ts';
import { useTopology, type Topology } from '../api/netedges.ts';
import { formatDateTime } from '../format.ts';
import { buildGraph, layout, portsLabel, type GraphLink, type GraphNode, type GraphOptions } from '../topology.ts';
import { DeviceDrawer } from './DeviceDrawer.tsx';
import './NetworkPage.css';

const width = 1000;
const height = 640;

/** Who talks to whom on the network: every device's neighbours and connections, as a graph. */
export function NetworkPage() {
  const topology = useTopology();
  const devices = useDevices();
  const [deviceId, setDeviceId] = useState<string>();
  const [opts, setOpts] = useState<GraphOptions>({
    neighbors: true,
    unknown: true,
  });
  const device = devices.data?.find((d) => d.id === deviceId);
  const t = topology.data;

  return (
    <>
      <main className="content">
        <div className="page-head">
          <div>
            <h1>Network</h1>
            <p className="muted">
              {t && t.reporting > 0
                ? `Neighbours and connections, as ${String(t.reporting)} ${t.reporting === 1 ? 'agent reports' : 'agents report'} them${t.updated_at ? `; last changed ${formatDateTime(t.updated_at)}` : ''}`
                : 'Neighbours and connections, as agents report them'}
            </p>
          </div>
          <button
            className="btn btn-ghost"
            type="button"
            disabled={topology.isFetching}
            onClick={() => {
              void topology.refetch();
            }}
          >
            Refresh
          </button>
        </div>
        {topology.isError ? (
          <div className="error-box" role="alert">
            Cannot read the network edges: {topology.error.message}
          </div>
        ) : !t ? (
          <p className="muted">Loading…</p>
        ) : t.reporting === 0 ? (
          <div className="empty">
            <h2>No agent reports edges</h2>
            <p className="muted">
              Start an agent with <code>--allow-net-edges</code> (Linux) to see its neighbours and connections here.
            </p>
          </div>
        ) : t.edges.length === 0 ? (
          <div className="empty">
            <h2>Nothing reported yet</h2>
            <p className="muted">Agents report their edges every minute. Refresh in a moment.</p>
          </div>
        ) : (
          <>
            <div className="topo-bar">
              <label>
                <input
                  type="checkbox"
                  checked={opts.neighbors}
                  onChange={(e) => {
                    setOpts({ ...opts, neighbors: e.target.checked });
                  }}
                />
                Neighbours
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={opts.unknown}
                  onChange={(e) => {
                    setOpts({ ...opts, unknown: e.target.checked });
                  }}
                />
                Unknown addresses
              </label>
              <Legend />
            </div>
            <TopologyGraph topology={t} opts={opts} onDevice={setDeviceId} />
          </>
        )}
      </main>
      {device ? (
        <DeviceDrawer
          device={device}
          onClose={() => {
            setDeviceId(undefined);
          }}
        />
      ) : null}
    </>
  );
}

function Legend() {
  return (
    <span className="topo-legend muted small">
      <span>
        <svg width="14" height="14" aria-hidden="true">
          <circle className="topo-node device reports" cx="7" cy="7" r="5" />
        </svg>
        device
      </span>
      <span>
        <svg width="14" height="14" aria-hidden="true">
          <circle className="topo-node hub" cx="7" cy="7" r="5" />
        </svg>
        hub
      </span>
      <span>
        <svg width="14" height="14" aria-hidden="true">
          <circle className="topo-node host" cx="7" cy="7" r="5" />
        </svg>
        host
      </span>
      <span>
        <svg width="14" height="14" aria-hidden="true">
          <circle className="topo-node unknown" cx="7" cy="7" r="4" />
        </svg>
        unknown
      </span>
      <span>
        <svg width="22" height="10" aria-hidden="true">
          <line className="topo-link connection" x1="1" y1="5" x2="21" y2="5" />
        </svg>
        connection
      </span>
      <span>
        <svg width="22" height="10" aria-hidden="true">
          <line className="topo-link neighbor" x1="1" y1="5" x2="21" y2="5" />
        </svg>
        neighbour
      </span>
    </span>
  );
}

const radius: Record<GraphNode['kind'], number> = {
  hub: 14,
  device: 11,
  host: 8,
  unknown: 5,
};

function TopologyGraph({
  topology,
  opts,
  onDevice,
}: {
  topology: Topology;
  opts: GraphOptions;
  onDevice: (id: string) => void;
}) {
  const [hover, setHover] = useState<string>();
  const [view, setView] = useState<View>(fit);
  const svg = useRef<SVGSVGElement>(null);
  // Pointers on the map: one drags it, two pinch it. `dragged` tells a click that ends a drag from a real one.
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const dragged = useRef(false);

  /** A pointer position in the drawing's own units, whatever size the map is shown at. */
  const toBox = (clientX: number, clientY: number) => {
    const m = svg.current?.getScreenCTM();
    if (!m) {
      return { x: width / 2, y: height / 2 };
    }
    const p = new DOMPoint(clientX, clientY).matrixTransform(m.inverse());
    return { x: p.x, y: p.y };
  };

  // The wheel zooms around the pointer. React's wheel listener is passive, so this one is set by hand to stop the page scrolling.
  useEffect(() => {
    const el = svg.current;
    if (!el) {
      return;
    }
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const p = toBox(e.clientX, e.clientY);
      setView((v) => zoomAt(v, e.deltaY < 0 ? 1.15 : 1 / 1.15, p.x, p.y, width, height));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => {
      el.removeEventListener('wheel', onWheel);
    };
  }, []);

  const onPointerDown = (e: ReactPointerEvent<SVGSVGElement>) => {
    pointers.current.set(e.pointerId, toBox(e.clientX, e.clientY));
    dragged.current = false;
  };
  const onPointerMove = (e: ReactPointerEvent<SVGSVGElement>) => {
    const before = pointers.current.get(e.pointerId);
    if (!before) {
      return;
    }
    const now = toBox(e.clientX, e.clientY);
    const others = [...pointers.current.entries()].filter(([id]) => id !== e.pointerId).map(([, p]) => p);
    const other = others[0];
    if (other) {
      // Pinch: zoom by how much the two fingers moved apart, around the point between them.
      const was = Math.hypot(before.x - other.x, before.y - other.y) || 1;
      const is = Math.hypot(now.x - other.x, now.y - other.y) || 1;
      dragged.current = true;
      setView((v) => zoomAt(v, is / was, (now.x + other.x) / 2, (now.y + other.y) / 2, width, height));
    } else {
      const dx = now.x - before.x;
      const dy = now.y - before.y;
      if (!dragged.current && Math.hypot(dx, dy) < 4) {
        return;
      }
      dragged.current = true;
      setView((v) => panBy(v, dx, dy, width, height));
    }
    pointers.current.set(e.pointerId, now);
  };
  const onPointerEnd = (e: ReactPointerEvent<SVGSVGElement>) => {
    pointers.current.delete(e.pointerId);
  };
  const zoomBy = (factor: number) => {
    setView((v) => zoomAt(v, factor, width / 2, height / 2, width, height));
  };
  const { nodes, links } = useMemo(() => {
    const g = buildGraph(topology, opts);
    return { nodes: layout(g.nodes, g.links, width, height), links: g.links };
  }, [topology, opts]);
  const at = new Map(nodes.map((n) => [n.id, n]));
  const near = (l: GraphLink) => hover === undefined || l.a === hover || l.b === hover;
  const nearNode = (id: string) => hover === undefined || id === hover || links.some((l) => near(l) && (l.a === id || l.b === id));

  return (
    <div className="topo-wrap">
      <div className="range-picker topo-zoom" role="group" aria-label="Zoom">
        <button
          type="button"
          className="range-option"
          aria-label="Zoom out"
          onClick={() => {
            zoomBy(1 / 1.4);
          }}
        >
          −
        </button>
        <button
          type="button"
          className="range-option"
          onClick={() => {
            setView(fit);
          }}
        >
          Fit
        </button>
        <button
          type="button"
          className="range-option"
          aria-label="Zoom in"
          onClick={() => {
            zoomBy(1.4);
          }}
        >
          +
        </button>
      </div>
      <svg
        ref={svg}
        className="topo"
        viewBox={`0 0 ${String(width)} ${String(height)}`}
        role="img"
        aria-label="Network graph. Drag to move it; scroll, pinch or use the buttons to zoom."
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerEnd}
        onPointerCancel={onPointerEnd}
        onPointerLeave={onPointerEnd}
      >
        <defs>
          <marker id="topo-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" className="topo-arrow" />
          </marker>
        </defs>
        <g transform={transformOf(view)}>
          {links.map((l) => {
            const a = at.get(l.a);
            const b = at.get(l.b);
            if (!a || !b) {
              return null;
            }
            // Point the arrow at the server, stopping at its circle.
            const [from, to] = l.server === l.a ? [b, a] : [a, b];
            const d = Math.hypot(to.x - from.x, to.y - from.y) || 1;
            const end = l.server ? radius[to.kind] + 3 : 0;
            const x2 = to.x - ((to.x - from.x) / d) * end;
            const y2 = to.y - ((to.y - from.y) / d) * end;
            return (
              <g key={`${l.a}|${l.b}`} className={near(l) ? undefined : 'dim'}>
                <line
                  className={`topo-link ${l.kind}`}
                  x1={from.x}
                  y1={from.y}
                  x2={x2}
                  y2={y2}
                  markerEnd={l.server ? 'url(#topo-arrow)' : undefined}
                >
                  <title>
                    {l.kind === 'connection'
                      ? `${from.name} → ${to.name}: port ${l.ports.join(', ')} (${String(l.count)} connection${l.count === 1 ? '' : 's'})`
                      : `${a.name} and ${b.name} are neighbours`}
                  </title>
                </line>
                {l.ports.length ? <PortLabel x1={from.x} y1={from.y} x2={to.x} y2={to.y} ports={l.ports} /> : null}
              </g>
            );
          })}
          {nodes.map((n) => {
            const device = n.kind === 'device' ? n.device_id : undefined;
            const open = device
              ? () => {
                  // The click that ends a drag moves the map; it does not open a device.
                  if (dragged.current) {
                    dragged.current = false;
                    return;
                  }
                  onDevice(device);
                }
              : undefined;
            return (
              <g
                key={n.id}
                className={`topo-item${device ? ' clickable' : ''}${nearNode(n.id) ? '' : ' dim'}`}
                transform={`translate(${String(n.x)} ${String(n.y)})`}
                tabIndex={device ? 0 : undefined}
                role={device ? 'button' : undefined}
                aria-label={device ? `Open ${n.name}` : undefined}
                onClick={open}
                onKeyDown={(e) => {
                  if (open && (e.key === 'Enter' || e.key === ' ')) {
                    e.preventDefault();
                    open();
                  }
                }}
                onMouseEnter={() => {
                  setHover(n.id);
                }}
                onMouseLeave={() => {
                  setHover(undefined);
                }}
              >
                <circle className={`topo-node ${n.kind}${n.reports ? ' reports' : ''}`} r={radius[n.kind]} />
                <text className={`topo-label ${n.kind}`} y={radius[n.kind] + 14}>
                  {n.name.length > 22 ? `${n.name.slice(0, 21)}…` : n.name}
                </text>
                {hover === n.id && n.ip && n.ip !== n.name ? (
                  <text className="topo-addr" y={radius[n.kind] + 27}>
                    {n.ip}
                  </text>
                ) : null}
                <title>{`${n.name} (${n.kind}${n.ip ? `, ${n.ip}` : ''})`}</title>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

/** A link's ports, at its middle and along it, kept upright. */
function PortLabel({ x1, y1, x2, y2, ports }: { x1: number; y1: number; x2: number; y2: number; ports: number[] }) {
  let angle = (Math.atan2(y2 - y1, x2 - x1) * 180) / Math.PI;
  if (angle > 90) {
    angle -= 180;
  } else if (angle <= -90) {
    angle += 180;
  }
  const x = (x1 + x2) / 2;
  const y = (y1 + y2) / 2;
  // As many ports as fit between the two nodes' circles and labels (about 7px a character).
  const room = Math.hypot(x2 - x1, y2 - y1) - 60;
  return (
    <text className="topo-port" x={x} y={y} dy="-4" transform={`rotate(${angle.toFixed(1)} ${x.toFixed(1)} ${y.toFixed(1)})`}>
      {portsLabel(ports, Math.floor(room / 7))}
    </text>
  );
}
