// The Cluster page's actions and states. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { actionEffect, memberActions, memberState, refusalMessage } from '../src/cluster.ts';

const member = (over) => ({
  id: 'hub-b',
  address: '10.0.0.2:7445',
  roles: ['storage', 'master'],
  allowed_roles: ['node', 'storage', 'master'],
  state: 'alive',
  ...over,
});

test('memberActions demotes held roles, promotes allowed ones, and removes others', () => {
  assert.deepEqual(
    memberActions(member(), 'hub-a').map((a) => a.label),
    ['Demote from storage', 'Demote from master', 'Remove'],
  );
  assert.deepEqual(
    memberActions(member({ roles: ['master'] }), 'hub-a').map((a) => [a.op, a.role]),
    [
      ['promote', 'storage'],
      ['demote', 'master'],
      ['remove', undefined],
    ],
  );
});

test('memberActions offers no role beyond --allow-roles and no self-removal', () => {
  const m = member({ id: 'hub-a', roles: ['storage'], allowed_roles: ['storage'] });
  assert.deepEqual(
    memberActions(m, 'hub-a').map((a) => a.label),
    ['Demote from storage'],
  );
});

test('memberState shows syncing, draining progress and failures', () => {
  assert.deepEqual(memberState(member()), { label: 'alive', tone: 'ok' });
  assert.deepEqual(memberState(member({ syncing: true })), { label: 'syncing', tone: 'warn' });
  assert.deepEqual(memberState(member({ draining: true, progress: 40 })), { label: 'draining 40%', tone: 'warn' });
  assert.deepEqual(memberState(member({ state: 'dead', syncing: true })), { label: 'dead', tone: 'bad' });
  assert.deepEqual(memberState(member({ state: 'left' })), { label: 'left', tone: 'muted' });
});

test('actionEffect names the member and what happens', () => {
  for (const a of memberActions(member({ roles: [] }), 'hub-a').concat(memberActions(member(), 'hub-a'))) {
    const text = actionEffect(a, 'hub-b');
    assert.ok(text.includes('hub-b'), text);
  }
  assert.match(actionEffect({ op: 'demote', role: 'master', label: '' }, 'hub-b'), /CA key/);
  assert.match(actionEffect({ op: 'promote', role: 'storage', label: '' }, 'hub-b'), /syncing/);
});

test('refusalMessage words denials and keeps the hub reason otherwise', () => {
  assert.match(refusalMessage('forbidden', 'denied by policy'), /policy/);
  assert.match(refusalMessage('isolated', 'x'), /no other member/);
  assert.equal(refusalMessage('last_master', 'the last master cannot be demoted'), 'the last master cannot be demoted');
});
