// The network topology graph: merged links, filters and a deterministic layout. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildGraph, layout, portsLabel } from '../src/topology.ts';

const topology = {
  reporting: 2,
  updated_at: '2026-01-01T00:00:00Z',
  nodes: [
    { id: 'device:nas', kind: 'device', name: 'nas', device_id: 'nas', reports: true },
    { id: 'device:pi', kind: 'device', name: 'pi', device_id: 'pi', reports: true },
    { id: 'device:quiet', kind: 'device', name: 'quiet', device_id: 'quiet', reports: true },
    { id: 'hub', kind: 'hub', name: 'hub host' },
    { id: 'host:aa:bb:cc:00:00:01', kind: 'host', name: 'router', ip: '192.0.2.1' },
    { id: 'ip:198.51.100.9', kind: 'unknown', name: '198.51.100.9', ip: '198.51.100.9' },
  ],
  edges: [
    { kind: 'connection', from: 'device:pi', to: 'device:nas', port: 445, count: 2 },
    { kind: 'connection', from: 'device:pi', to: 'device:nas', port: 22, count: 1 },
    { kind: 'connection', from: 'device:pi', to: 'hub', port: 7443, count: 1 },
    { kind: 'connection', from: 'hub', to: 'device:pi', port: 22, count: 1 },
    { kind: 'connection', from: 'device:pi', to: 'ip:198.51.100.9', port: 443, count: 1 },
    { kind: 'neighbor', from: 'device:nas', to: 'device:pi' },
    { kind: 'neighbor', from: 'device:pi', to: 'host:aa:bb:cc:00:00:01' },
  ],
};

const all = { neighbors: true, unknown: true };

test('one link per pair, connections over neighbours, ports merged', () => {
  const { links } = buildGraph(topology, all);
  const pi = links.find((l) => l.a === 'device:nas' && l.b === 'device:pi');
  assert.deepEqual(pi, { a: 'device:nas', b: 'device:pi', kind: 'connection', ports: [22, 445], server: 'device:nas', count: 3 });
  const hub = links.find((l) => l.b === 'hub');
  assert.equal(hub.server, undefined, 'connections both ways: no single server');
  assert.deepEqual(hub.ports, [22, 7443]);
  const router = links.find((l) => l.b === 'host:aa:bb:cc:00:00:01');
  assert.equal(router.kind, 'neighbor');
  assert.equal(links.length, 4);
});

test('filters drop links and the nodes they leave alone, never a reporting device or the hub', () => {
  const { nodes, links } = buildGraph(topology, { neighbors: false, unknown: false });
  assert.deepEqual(
    nodes.map((n) => n.id).sort(),
    ['device:nas', 'device:pi', 'device:quiet', 'hub'],
  );
  assert.ok(links.every((l) => l.kind === 'connection'));
  assert.equal(links.length, 2);
});

test('layout is deterministic and stays in the box', () => {
  const g = buildGraph(topology, all);
  const one = layout(g.nodes, g.links, 1000, 640);
  const two = layout(g.nodes, g.links, 1000, 640);
  assert.deepEqual(one, two);
  assert.equal(one.length, g.nodes.length);
  for (const n of one) {
    assert.ok(Number.isFinite(n.x) && Number.isFinite(n.y), `${n.id} placed`);
    assert.ok(n.x >= 59.99 && n.x <= 940.01 && n.y >= 59.99 && n.y <= 580.01, `${n.id} at ${n.x},${n.y}`);
  }
  const placed = new Set(one.map((n) => `${Math.round(n.x)},${Math.round(n.y)}`));
  assert.equal(placed.size, one.length, 'no two nodes on one spot');
});

test('layout of thirty nodes keeps them apart', () => {
  const nodes = Array.from({ length: 30 }, (_, i) => ({ id: `device:d${String(i)}`, kind: 'device', name: `d${String(i)}` }));
  const links = nodes.slice(1).map((n, i) => ({ a: nodes[i % 5].id, b: n.id, kind: 'connection', ports: [22], count: 1 }));
  const placed = layout(nodes, links, 1000, 640);
  let closest = Infinity;
  for (let i = 0; i < placed.length; i++) {
    for (let j = i + 1; j < placed.length; j++) {
      closest = Math.min(closest, Math.hypot(placed[i].x - placed[j].x, placed[i].y - placed[j].y));
    }
  }
  assert.ok(closest > 30, `closest pair ${String(closest)} apart`);
});

test('no nodes, no layout', () => {
  assert.deepEqual(layout([], [], 1000, 640), []);
});

test('ports label', () => {
  assert.equal(portsLabel([22]), '22');
  assert.equal(portsLabel([22, 80, 443]), '22, 80, 443');
  assert.equal(portsLabel([22, 80, 443, 7443, 8080]), '22, 80, 443 +2');
  // A short link: as many as fit, at least one.
  assert.equal(portsLabel([22, 80, 443, 7443, 8080], 10), '22, 80 +3');
  assert.equal(portsLabel([17443, 17461, 17462], 8), '17443 +2');
  assert.equal(portsLabel([17443], 0), '17443');
});
