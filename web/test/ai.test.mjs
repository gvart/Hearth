// The AI settings form and the Explain card's log field. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { aiEditBody, aiFormReady, parseLogSources } from '../src/ai.ts';

const form = (patch) => ({ provider: 'openai', base_url: '', model: '', api_key: '', clear_api_key: false, ...patch });

test('turning AI off sends only the provider', () => {
  assert.deepEqual(aiEditBody(form({ provider: '', base_url: 'x' }), 'r1'), { provider: '', revision: 'r1' });
});

test('an edit trims, and clears the key only when no new one is typed', () => {
  const body = aiEditBody(form({ base_url: ' http://h/v1 ', model: ' m ', api_key: ' k ', clear_api_key: true }), 'r');
  assert.deepEqual(body, { provider: 'openai', base_url: 'http://h/v1', model: 'm', api_key: 'k', clear_api_key: false, revision: 'r' });
  assert.equal(aiEditBody(form({ clear_api_key: true }), 'r').clear_api_key, true);
});

test('a form is ready when its provider has what it needs', () => {
  assert.equal(aiFormReady(form({ provider: '' }), false, false), true);
  assert.equal(aiFormReady(form({}), false, false), false, 'openai needs an address and a model');
  assert.equal(aiFormReady(form({ base_url: 'http://h/v1', model: 'm' }), false, false), true, 'no key needed');
  assert.equal(aiFormReady(form({ provider: 'anthropic' }), false, false), false, 'anthropic needs a key');
  assert.equal(aiFormReady(form({ provider: 'anthropic' }), true, true), true, 'the stored key, same target');
  assert.equal(aiFormReady(form({ provider: 'anthropic' }), true, false), false, 'not carried to a new target');
  assert.equal(aiFormReady(form({ provider: 'anthropic', api_key: 'k' }), false, false), true);
});

test('log sources are manager:name, at most three', () => {
  assert.deepEqual(parseLogSources(''), { sources: [], error: '' });
  assert.deepEqual(parseLogSources('systemd:a, docker:b\nsystemd:a'), { sources: ['systemd:a', 'docker:b'], error: '' });
  assert.match(parseLogSources('nginx').error, /manager:name/);
  assert.match(parseLogSources('systemd:').error, /manager:name/);
  assert.match(parseLogSources('a:1,a:2,a:3,a:4').error, /three/);
});
