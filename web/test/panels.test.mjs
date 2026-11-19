// Panels: the share link route, kiosk mode and the builder's edits. Run with
// `npm test` in web/. The pages themselves are checked in a browser (see the
// PR); node cannot import .tsx.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { addDevice, isKiosk, moveWidget, panelToken, restartServices, shareURL, toggleRestart, toInput } from '../src/panels.ts';

describe('panelToken', () => {
  const cases = [
    ['/p/ABC123', 'ABC123'],
    ['/p/', null],
    ['/p', null],
    ['/', null],
    ['/p/ABC/extra', null],
    ['/devices/p/ABC', null],
  ];
  for (const [path, want] of cases) {
    test(path, () => {
      assert.equal(panelToken(path), want);
    });
  }
});

describe('isKiosk', () => {
  const cases = [
    ['?kiosk=1', true],
    ['?kiosk=true', true],
    ['?kiosk=0', false],
    ['', false],
    ['?other=1', false],
  ];
  for (const [search, want] of cases) {
    test(search || 'none', () => {
      assert.equal(isKiosk(search), want);
    });
  }
});

test('shareURL', () => {
  assert.equal(shareURL('http://hub.lan:7080', '/p/T', false), 'http://hub.lan:7080/p/T');
  assert.equal(shareURL('http://hub.lan:7080', '/p/T', true), 'http://hub.lan:7080/p/T?kiosk=1');
});

test('restartServices offers only what the agent allows', () => {
  assert.deepEqual(restartServices(undefined), []);
  assert.deepEqual(restartServices({ facts: {} }), []);
  assert.deepEqual(restartServices({ facts: { ceiling: { exec: [], restart: ['systemd:kodi', 'docker:nginx'], probe: false } } }), [
    'docker:nginx',
    'systemd:kodi',
  ]);
});

describe('builder edits', () => {
  const empty = { name: 'Hall', widgets: [] };

  test('a device is added once', () => {
    const p = addDevice(addDevice(empty, 'pi'), 'pi');
    assert.deepEqual(p.widgets, [{ kind: 'device', entity: 'pi', actions: [] }]);
    assert.equal(addDevice(empty, ''), empty);
  });

  test('a restart is allowed and taken back', () => {
    let p = addDevice(addDevice(empty, 'pi'), 'nas');
    p = toggleRestart(p, 1, 'docker:nginx', true);
    p = toggleRestart(p, 1, 'docker:nginx', true);
    assert.deepEqual(p.widgets[1].actions, [{ action: 'device.restart', service: 'docker:nginx' }]);
    assert.deepEqual(p.widgets[0].actions, []);
    p = toggleRestart(p, 1, 'docker:nginx', false);
    assert.deepEqual(p.widgets[1].actions, []);
  });

  test('widgets move and are removed', () => {
    const p = addDevice(addDevice(addDevice(empty, 'a'), 'b'), 'c');
    assert.deepEqual(
      moveWidget(p, 2, -1).widgets.map((w) => w.entity),
      ['a', 'c', 'b'],
    );
    assert.deepEqual(
      moveWidget(p, 0, -1).widgets.map((w) => w.entity),
      ['a', 'b', 'c'],
    );
    assert.deepEqual(
      moveWidget(p, 1, 0).widgets.map((w) => w.entity),
      ['a', 'c'],
    );
  });

  test('a saved panel keeps its widget IDs and drops what the hub sets', () => {
    const saved = {
      id: 'p1',
      name: 'Hall',
      links: [],
      created_at: '',
      updated_at: '',
      widgets: [
        {
          id: 'w1',
          kind: 'device',
          entity: 'pi',
          actions: [{ id: 'device.restart:docker:nginx', action: 'device.restart', service: 'docker:nginx', class: 'safe' }],
        },
      ],
    };
    assert.deepEqual(toInput(saved), {
      name: 'Hall',
      widgets: [{ id: 'w1', kind: 'device', entity: 'pi', actions: [{ action: 'device.restart', service: 'docker:nginx' }] }],
    });
  });
});
