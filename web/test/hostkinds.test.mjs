// The kinds of discovered host: a label and a mark each. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { hostKinds, hostKindTitle } from '../src/hostkinds.ts';

test('every kind the hub classifies has a label and a mark', () => {
  // The kinds of internal/discovery/classify.go.
  const go = readFileSync(new URL('../../internal/discovery/classify.go', import.meta.url), 'utf8');
  const kinds = [...go.matchAll(/Kind\w+ Kind = "(\w+)"/g)].map((m) => m[1]).sort();
  assert.equal(kinds.length, 8);
  assert.deepEqual(Object.keys(hostKinds).sort(), kinds);
  const labels = new Set();
  for (const [kind, { label, path }] of Object.entries(hostKinds)) {
    assert.ok(label, kind);
    assert.ok(!labels.has(label), `${kind} repeats the label ${label}`);
    labels.add(label);
    assert.match(path, /^M[\d.\sMmHhVvLlZz-]+$/, `${kind}: ${path}`);
    for (const n of path.match(/\d+(\.\d+)?/g)) {
      assert.ok(Number(n) <= 16, `${kind} draws outside the 16 × 16 grid: ${path}`);
    }
  }
});

test('hostKindTitle tells the services and whether an agent fits', () => {
  assert.equal(hostKindTitle({ kind: 'unknown', services: [], agent_capable: false }), 'Unknown');
  assert.equal(
    hostKindTitle({ kind: 'computer', services: ['_ssh._tcp', '_workstation._tcp'], agent_capable: true }),
    'Computer. Announces _ssh._tcp, _workstation._tcp. Looks able to run a Hearth agent',
  );
  assert.equal(
    hostKindTitle({ kind: 'nas', services: [], agent_capable: true }),
    'NAS. Looks able to run a Hearth agent',
  );
});
