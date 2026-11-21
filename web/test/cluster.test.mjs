// The Cluster page's actions and states. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  actionEffect,
  caRefusalMessage,
  caStepEffect,
  caSteps,
  hubProgress,
  memberActions,
  memberState,
  refusalMessage,
  waitingFor,
} from '../src/cluster.ts';

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

const newFP = 'b'.repeat(64);
const rotation = (over) => ({
  new_ca_fp: newFP,
  old_ca_fp: 'a'.repeat(64),
  stage: 'started',
  active: true,
  started_at: '2026-11-21T10:00:00Z',
  updated_at: '2026-11-21T10:00:00Z',
  owner: 'hub-a',
  owner_alive: true,
  ...over,
});
const hub = (over) => ({
  id: 'hub-a',
  master: true,
  serving: 'a'.repeat(16),
  next: 'b'.repeat(16),
  has_next_cert: true,
  has_next_key: true,
  ...over,
});

test('hubProgress says what a member still lacks for the stage', () => {
  const rot = rotation();
  assert.deepEqual(hubProgress(hub(), rot), { ready: true, label: 'ready', tone: 'ok' });
  assert.equal(hubProgress(hub({ next: undefined }), rot).label, 'fetching the new CA');
  assert.equal(hubProgress(hub({ has_next_cert: false }), rot).label, 'fetching its certificate');
  assert.equal(hubProgress(hub({ has_next_key: false }), rot).label, 'fetching the key');
  // A storage-only member never holds the key.
  assert.equal(hubProgress(hub({ master: false, has_next_key: false }), rot).ready, true);
  assert.deepEqual(hubProgress(hub({ error: 'dead' }), rot), { ready: false, label: 'dead', tone: 'bad' });
  assert.equal(hubProgress(hub({ error: 'it says nothing of the hub CA yet' }), rot).label, 'no answer yet');
  assert.equal(hubProgress(hub(), rotation({ stage: 'cutover' })).label, 'cutting over');
  assert.equal(hubProgress(hub({ cut_over: true }), rotation({ stage: 'cutover' })).ready, true);
});

test('waitingFor names the members a finish waits for', () => {
  const st = { node_id: 'hub-a', rotation: rotation(), hubs: [hub(), hub({ id: 'hub-c', error: 'dead' })] };
  assert.deepEqual(waitingFor(st), ['hub-c (dead)']);
  assert.deepEqual(waitingFor({ ...st, rotation: rotation({ active: false, stage: 'finished' }) }), []);
});

test('caSteps offers a start, or a finish and an abort before the cutover', () => {
  assert.deepEqual(caSteps(undefined), ['rotate']);
  assert.deepEqual(caSteps({ node_id: 'a', hubs: [] }), ['rotate']);
  assert.deepEqual(caSteps({ node_id: 'a', hubs: [], rotation: rotation({ active: false, stage: 'aborted' }) }), [
    'rotate',
  ]);
  assert.deepEqual(caSteps({ node_id: 'a', hubs: [], rotation: rotation() }), ['finish', 'abort']);
  assert.deepEqual(caSteps({ node_id: 'a', hubs: [], rotation: rotation({ stage: 'cutover' }) }), ['finish']);
});

test('caStepEffect states the consequences', () => {
  assert.match(caStepEffect('rotate').join(' '), /Every member must be up/);
  assert.match(caStepEffect('finish').join(' '), /down stops the finish/);
  assert.match(caStepEffect('finish').join(' '), /ca\.crt/);
  assert.match(caStepEffect('abort').join(' '), /enroll again/);
});

test('caRefusalMessage names the owner and keeps the hub reason otherwise', () => {
  const msg = caRefusalMessage('rotation_owner', 'another master drives it', rotation({ owner_url: 'https://hub-a:7443' }));
  assert.match(msg, /hub-a owns this rotation/);
  assert.match(msg, /https:\/\/hub-a:7443/);
  assert.equal(caRefusalMessage('rotation_failed', 'these members are down: hub-c', rotation()), 'these members are down: hub-c');
  assert.match(caRefusalMessage('isolated', 'x', undefined), /no other member/);
});
