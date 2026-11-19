// The telemetry prompt: when it asks, what it says is sent, and that an answer
// is stored on the hub. Run with `npm test` in web/. The card's rendering is
// checked in a browser (see the PR); node cannot import .tsx.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, describe, test } from 'node:test';
import { api } from '../src/api/client.ts';
import { telemetryFields, telemetryView } from '../src/telemetry.ts';

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('telemetryView', () => {
  const cases = [
    ['loading', undefined, 'loading'],
    ['unanswered asks', { answered: false, enabled: false, disabled_by_env: false }, 'ask'],
    ['yes', { answered: true, enabled: true, disabled_by_env: false }, 'on'],
    ['no', { answered: true, enabled: false, disabled_by_env: false }, 'off'],
    ['env off never asks', { answered: false, enabled: false, disabled_by_env: true }, 'env-off'],
    ['env off beats a stored yes', { answered: true, enabled: true, disabled_by_env: true }, 'env-off'],
  ];
  for (const [name, setting, want] of cases) {
    test(name, () => {
      assert.equal(telemetryView(setting), want);
    });
  }
});

test('the prompt lists what docs/telemetry.md lists', () => {
  const doc = readFileSync(new URL('../../docs/telemetry.md', import.meta.url), 'utf8');
  assert.equal(telemetryFields.length, 5);
  for (const key of ['install_id', 'version', 'os', 'arch', 'devices', 'integrations']) {
    assert.match(doc, new RegExp('`' + key + '`'), `docs/telemetry.md names ${key}`);
  }
});

describe('storing the answer', () => {
  for (const enabled of [true, false]) {
    test(`answer ${String(enabled)} is a PUT to /api/v1/telemetry`, async () => {
      const calls = [];
      globalThis.fetch = (url, init) => {
        calls.push({ url, init });
        return Promise.resolve(
          new Response(JSON.stringify({ answered: true, enabled, disabled_by_env: false }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        );
      };
      const got = await api.setTelemetry(enabled);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].url, '/api/v1/telemetry');
      assert.equal(calls[0].init.method, 'PUT');
      assert.deepEqual(JSON.parse(calls[0].init.body), { enabled });
      assert.equal(telemetryView(got), enabled ? 'on' : 'off');
    });
  }
});
