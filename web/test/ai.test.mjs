// The AI settings form, the Explain card's log field and automation drafts. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { aiEditBody, aiFormReady, draftNotice, parseLogSources } from '../src/ai.ts';
import { readAutomation } from '../src/automations/model.ts';

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

test('a draft says who wrote it and what is left to do', () => {
  const valid = draftNotice({ model: 'llama3.2', attempts: 1, valid: true, problems: [] });
  assert.match(valid, /^Drafted by llama3\.2\. Nothing is saved yet\. .*Save\.$/);
  const fixed = draftNotice({ model: 'm', attempts: 2, valid: false, problems: [{}, {}] });
  assert.match(fixed, /\(2 tries\).*2 problems\): fix them/);
  assert.match(draftNotice({ model: 'm', attempts: 2, valid: false, problems: [{}] }), /1 problem\): fix it/);
});

test('the draft the model is shown opens in the visual editor', () => {
  // DraftExample in internal/ai/automation.go: the shape a draft takes.
  const go = readFileSync(new URL('../../internal/ai/automation.go', import.meta.url), 'utf8');
  const example = /const DraftExample = `([\s\S]*?)`/.exec(go)?.[1];
  assert.ok(example, 'DraftExample found');
  const read = readAutomation(example);
  assert.equal(read.ok, true, JSON.stringify(read.problems));
});
