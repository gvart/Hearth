// A device's hub on its page: roles, and when "Make this device a hub" is offered. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { capsLine, hubMember, hubPlatform, hubRoleLine, makeHubBlocked, makeHubEffect } from '../src/devicehub.ts';

const hub = (over) => ({
  roles: [],
  allowed_roles: [],
  masters: 1,
  storage: 1,
  max_masters: 3,
  max_storage: 5,
  agent_only_command: 'curl -fsSL http://hub.lan:7080/install.sh | sh -s -- --agent-only',
  ...over,
});

test('an agent has no member; a hub is one, with its roles and state', () => {
  assert.equal(hubMember(hub()), undefined);
  assert.match(hubRoleLine(hub()), /Agent only: the hub service is not installed/);
  const h = hub({ node_id: 'mac-1a2b', roles: ['storage', 'master'], allowed_roles: ['storage', 'master'], state: 'alive' });
  assert.deepEqual(hubMember(h), {
    id: 'mac-1a2b',
    address: '',
    roles: ['storage', 'master'],
    allowed_roles: ['storage', 'master'],
    state: 'alive',
  });
  assert.match(hubRoleLine(h), /^Master and storage/);
  assert.match(hubRoleLine(hub({ node_id: 'pi', roles: ['storage'] })), /^Storage/);
  assert.match(hubRoleLine(hub({ node_id: 'pi', roles: ['master'] })), /^Master:/);
  assert.equal(hubMember(hub({ node_id: 'pi' }))?.state, 'unknown');
});

test('only 64-bit Linux and macOS run a hub', () => {
  assert.ok(hubPlatform('debian 12', 'arm64'));
  assert.ok(hubPlatform('darwin 26.7.3', 'arm64'));
  assert.ok(hubPlatform('ubuntu 24.04', 'amd64'));
  assert.ok(!hubPlatform('raspbian 12', 'arm'));
  assert.ok(!hubPlatform('Microsoft Windows 11 Pro', 'amd64'));
  assert.ok(!hubPlatform('android 14', 'arm64'));
  assert.ok(hubPlatform('', ''), 'not reported yet: the device checks');
  assert.match(makeHubBlocked(hub(), 'raspbian 12', 'arm') ?? '', /64-bit Linux or macOS/);
});

test('a Mac is offered a hub; a full storage cap offers none', () => {
  assert.equal(makeHubBlocked(hub(), 'darwin 26.7.3', 'arm64'), undefined);
  assert.match(makeHubBlocked(hub({ storage: 5 }), 'darwin 26.7.3', 'arm64') ?? '', /5 storage members, the most devices become \(5\)/);
});

test('the effect says master while under the master cap, storage only past it', () => {
  assert.match(makeHubEffect(hub({ masters: 2 })), /master and a storage member: 2 of at most 3/);
  assert.match(makeHubEffect(hub({ masters: 3 })), /storage member only/);
  assert.equal(capsLine(hub({ masters: 2, storage: 4 })), '2 of 3 masters · 4 of 5 storage members');
});
