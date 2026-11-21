// The network topology graph: which nodes and links to draw, and where.
// Pure and deterministic, so `npm test` can check it.

import type { Topology, TopologyNode } from './api/netedges.ts';

/** A node to draw, placed by layout(). */
export interface GraphNode extends TopologyNode {
  x: number;
  y: number;
}

/** One line between two nodes: every edge between them, merged. */
export interface GraphLink {
  /** The two ends, in id order. */
  a: string;
  b: string;
  /** "connection" when any connection joins them, else "neighbor". */
  kind: 'connection' | 'neighbor';
  /** The server ports of the connections, ascending. */
  ports: number[];
  /** The connections' server: a or b when every connection goes to the same end. */
  server?: string;
  count: number;
}

export interface GraphOptions {
  /** Draw neighbour (ARP) links. */
  neighbors: boolean;
  /** Draw addresses the hub knows nothing of. */
  unknown: boolean;
}

/**
 * The nodes and links to draw. A node left without links by the options is
 * left out, except a device that reports edges and the hub.
 */
export function buildGraph(t: Topology, opts: GraphOptions): { nodes: TopologyNode[]; links: GraphLink[] } {
  const shown = new Map(t.nodes.filter((n) => opts.unknown || n.kind !== 'unknown').map((n) => [n.id, n]));
  const byPair = new Map<string, GraphLink>();
  for (const e of t.edges) {
    if ((e.kind === 'neighbor' && !opts.neighbors) || !shown.has(e.from) || !shown.has(e.to) || e.from === e.to) {
      continue;
    }
    const [a, b] = e.from < e.to ? [e.from, e.to] : [e.to, e.from];
    const key = `${a}\n${b}`;
    let l = byPair.get(key);
    if (!l) {
      l = { a, b, kind: 'neighbor', ports: [], count: 0 };
      byPair.set(key, l);
    }
    if (e.kind !== 'connection') {
      continue;
    }
    if (l.kind === 'neighbor') {
      l.kind = 'connection';
      l.server = e.to;
    } else if (l.server !== e.to) {
      l.server = undefined;
    }
    if (e.port !== undefined && !l.ports.includes(e.port)) {
      l.ports.push(e.port);
    }
    l.count += e.count ?? 0;
  }
  const links = [...byPair.values()];
  for (const l of links) {
    l.ports.sort((x, y) => x - y);
  }
  const linked = new Set(links.flatMap((l) => [l.a, l.b]));
  const nodes = [...shown.values()].filter((n) => linked.has(n.id) || n.reports || n.kind === 'hub');
  return { nodes, links };
}

const kindOrder: Record<TopologyNode['kind'], number> = { hub: 0, device: 1, host: 2, unknown: 3 };

/**
 * Places the nodes in a width × height box, leaving pad free at its edges:
 * a force layout (Fruchterman–Reingold) from a circle, run a fixed number of
 * steps, so the same graph always lands the same way.
 */
export function layout(nodes: TopologyNode[], links: GraphLink[], width: number, height: number, pad = 60): GraphNode[] {
  const sorted = nodes
    .slice()
    .sort((p, q) => kindOrder[p.kind] - kindOrder[q.kind] || p.id.localeCompare(q.id));
  const n = sorted.length;
  if (n === 0) {
    return [];
  }
  const w = width - 2 * pad;
  const h = height - 2 * pad;
  const degree = new Map<string, number>();
  for (const l of links) {
    degree.set(l.a, (degree.get(l.a) ?? 0) + 1);
    degree.set(l.b, (degree.get(l.b) ?? 0) + 1);
  }
  // Each node starts on a circle, in kind and id order. Its mass grows with
  // its links, so busy nodes (devices, the hub) push each other apart and
  // their labels do not collide.
  const pts = sorted.map((node, i) => ({
    node,
    x: Math.cos((2 * Math.PI * i) / n) * w * 0.4,
    y: Math.sin((2 * Math.PI * i) / n) * h * 0.4,
    m: Math.sqrt(1 + (degree.get(node.id) ?? 0)),
    dx: 0,
    dy: 0,
  }));
  const at = new Map(pts.map((p) => [p.node.id, p]));
  const pairs = links.flatMap((l) => {
    const p = at.get(l.a);
    const q = at.get(l.b);
    // Neighbours pull less than connections: who talks to whom shapes the graph.
    return p && q ? [[p, q, l.kind === 'connection' ? 0.5 : 0.3] as const] : [];
  });
  const k = Math.sqrt((w * h) / n) * 0.9; // the ideal distance between nodes
  const steps = 300;
  let temp = Math.min(w, h) / 8;
  for (let step = 0; step < steps; step++) {
    for (const p of pts) {
      // A pull to the centre keeps nodes without links from drifting off.
      p.dx = -p.x * 0.01 * (k / 10);
      p.dy = -p.y * 0.01 * (k / 10);
    }
    pts.forEach((p, i) => {
      pts.slice(i + 1).forEach((q, j) => {
        let ux = p.x - q.x;
        let uy = p.y - q.y;
        let d = Math.hypot(ux, uy);
        if (d < 0.01) {
          // Coincident: part them along a fixed direction.
          ux = -0.01 * (j + 1);
          uy = 0.01;
          d = Math.hypot(ux, uy);
        }
        const f = (k * k * p.m * q.m) / d;
        p.dx += (ux / d) * f;
        p.dy += (uy / d) * f;
        q.dx -= (ux / d) * f;
        q.dy -= (uy / d) * f;
      });
    });
    for (const [p, q, weight] of pairs) {
      const ux = p.x - q.x;
      const uy = p.y - q.y;
      const d = Math.hypot(ux, uy) || 0.01;
      const f = (weight * d * d) / k;
      p.dx -= (ux / d) * f;
      p.dy -= (uy / d) * f;
      q.dx += (ux / d) * f;
      q.dy += (uy / d) * f;
    }
    for (const p of pts) {
      const d = Math.hypot(p.dx, p.dy);
      if (d > 0) {
        const move = Math.min(d, temp);
        p.x += (p.dx / d) * move;
        p.y += (p.dy / d) * move;
      }
    }
    temp = Math.max(temp * 0.985, 1);
  }
  // Fit the result into the box, stretched by at most half again along
  // one axis: labels are wide, so the width is worth using.
  const xs = pts.map((p) => p.x);
  const ys = pts.map((p) => p.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  let sx = maxX > minX ? w / (maxX - minX) : 1;
  let sy = maxY > minY ? h / (maxY - minY) : 1;
  sx = Math.min(sx, sy * 1.5);
  sy = Math.min(sy, sx * 1.5);
  const offX = pad + (w - (maxX - minX) * sx) / 2;
  const offY = pad + (h - (maxY - minY) * sy) / 2;
  const out = pts.map((p) => ({ ...p.node, x: offX + (p.x - minX) * sx, y: offY + (p.y - minY) * sy }));
  separate(out, width, height, pad);
  return out;
}

/** The rows of the tiered layout, top to bottom, and what each is called beside the map. */
export const tierOrder: TopologyNode['kind'][] = ['hub', 'device', 'host', 'unknown'];

export const tierLabel: Record<TopologyNode['kind'], string> = {
  hub: 'Hub',
  device: 'Devices',
  host: 'Hosts',
  unknown: 'Unknown',
};

/** A row of the tiered layout: its kind and the height it is drawn at. */
export interface TierRow {
  kind: TopologyNode['kind'];
  y: number;
}

/**
 * Places the nodes in rows by kind: the hub at the top, then devices, the
 * hosts they see, and addresses the hub knows nothing of. A kind with more
 * nodes than fit side by side (slot wide each) takes several rows. Within a
 * row a node sits under the middle of what it links to in the rows above, as
 * far as a few sweeps manage, so the lines cross less.
 */
export function tiers(
  nodes: TopologyNode[],
  links: GraphLink[],
  width: number,
  height: number,
  pad = 60,
  slot = 124,
): { nodes: GraphNode[]; rows: TierRow[] } {
  if (nodes.length === 0) {
    return { nodes: [], rows: [] };
  }
  const perRow = Math.max(1, Math.floor((width - 2 * pad) / slot));
  const peers = new Map<string, string[]>();
  for (const l of links) {
    peers.set(l.a, [...(peers.get(l.a) ?? []), l.b]);
    peers.set(l.b, [...(peers.get(l.b) ?? []), l.a]);
  }
  // Rows of ids, in kind order; a kind wraps into rows of the same length, give or take one.
  const rows: { kind: TopologyNode['kind']; ids: string[] }[] = [];
  for (const kind of tierOrder) {
    const ids = nodes
      .filter((n) => n.kind === kind)
      .map((n) => n.id)
      .sort((a, b) => a.localeCompare(b));
    const count = Math.ceil(ids.length / perRow);
    const size = Math.ceil(ids.length / Math.max(count, 1));
    for (let i = 0; i < count; i++) {
      rows.push({ kind, ids: ids.slice(i * size, (i + 1) * size) });
    }
  }
  // Where each node sits along its row, from 0 to 1, re-read after every sweep.
  const pos = new Map<string, number>();
  const place = (ids: string[]) => {
    ids.forEach((id, i) => pos.set(id, (i + 0.5) / ids.length));
  };
  rows.forEach((r) => {
    place(r.ids);
  });
  const rowOf = new Map(rows.flatMap((r, i) => r.ids.map((id) => [id, i] as const)));
  const sweep = (order: number[], towards: (other: number, own: number) => boolean) => {
    for (const i of order) {
      const row = rows[i];
      if (!row) {
        continue;
      }
      const middle = (id: string) => {
        const ps = (peers.get(id) ?? [])
          .filter((p) => towards(rowOf.get(p) ?? -1, i))
          .map((p) => pos.get(p) ?? 0.5);
        return ps.length > 0 ? ps.reduce((a, b) => a + b, 0) / ps.length : (pos.get(id) ?? 0.5);
      };
      const keyed = row.ids.map((id) => ({ id, at: middle(id) }));
      keyed.sort((a, b) => a.at - b.at || a.id.localeCompare(b.id));
      row.ids = keyed.map((k) => k.id);
      place(row.ids);
    }
  };
  const down = rows.map((_, i) => i);
  const up = down.slice().reverse();
  for (let pass = 0; pass < 3; pass++) {
    sweep(down, (other, own) => other >= 0 && other < own);
    sweep(up, (other, own) => other > own);
  }
  const at = new Map(nodes.map((n) => [n.id, n]));
  const h = height - 2 * pad;
  const w = width - 2 * pad;
  const out: GraphNode[] = [];
  const placed: TierRow[] = [];
  rows.forEach((row, i) => {
    const y = rows.length === 1 ? height / 2 : pad + (h * i) / (rows.length - 1);
    placed.push({ kind: row.kind, y });
    row.ids.forEach((id, j) => {
      const node = at.get(id);
      if (node) {
        out.push({ ...node, x: pad + (w * (j + 0.5)) / row.ids.length, y });
      }
    });
  });
  return { nodes: out, rows: placed };
}

/**
 * Nudges nodes apart whose labels would overlap: each node keeps a label-sized
 * ellipse (labelW × labelH) to itself, as far as a few passes manage.
 */
function separate(nodes: GraphNode[], width: number, height: number, pad: number, labelW = 120, labelH = 44) {
  for (let pass = 0; pass < 60; pass++) {
    let moved = false;
    for (const [i, p] of nodes.entries()) {
      for (const [j, q] of nodes.slice(i + 1).entries()) {
        const ux = (q.x - p.x) / labelW;
        const uy = (q.y - p.y) / labelH;
        const d = Math.hypot(ux, uy);
        if (d >= 1) {
          continue;
        }
        moved = true;
        // Coincident: part them sideways, in a fixed direction.
        const [nx, ny] = d > 0.001 ? [ux / d, uy / d] : [1, (j % 2) - 0.5];
        const push = (1 - d) / 2;
        p.x -= nx * push * labelW;
        p.y -= ny * push * labelH;
        q.x += nx * push * labelW;
        q.y += ny * push * labelH;
      }
    }
    for (const p of nodes) {
      p.x = Math.min(Math.max(p.x, pad), width - pad);
      p.y = Math.min(Math.max(p.y, pad), height - pad);
    }
    if (!moved) {
      return;
    }
  }
}

/**
 * The ports of a link as a label of at most maxChars characters: as many
 * ports as fit, at most three, then how many more; at least one port.
 */
export function portsLabel(ports: number[], maxChars = Infinity): string {
  for (let n = Math.min(ports.length, 3); n > 1; n--) {
    const s = ports.slice(0, n).join(', ') + (n < ports.length ? ` +${String(ports.length - n)}` : '');
    if (s.length <= maxChars) {
      return s;
    }
  }
  return ports.length > 1 ? `${String(ports[0])} +${String(ports.length - 1)}` : ports.join('');
}
