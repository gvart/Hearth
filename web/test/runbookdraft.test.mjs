// A runbook drafted from a recording, handed to the editor. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { clearRunbookDraft, readRunbookDraft, runbookDraftNotice, stashRunbookDraft } from '../src/runbookdraft.ts';

function memory() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, v),
    removeItem: (k) => m.delete(k),
    m,
  };
}

test('a stashed draft keeps only what the editor shows, until cleared', () => {
  const s = memory();
  const draft = { yaml: 'id: x\n', model: 'llama3.2', attempts: 2, valid: true, problems: [], sent: { messages: ['TRANSCRIPT'] } };
  assert.equal(stashRunbookDraft(draft, s), true);
  assert.ok(![...s.m.values()].join('').includes('TRANSCRIPT'), 'what was sent is never stashed');
  assert.deepEqual(readRunbookDraft(s), { yaml: 'id: x\n', model: 'llama3.2', attempts: 2, valid: true, problems: [] });
  clearRunbookDraft(s);
  assert.equal(readRunbookDraft(s), null, 'cleared');
});

test('nothing stashed, or something broken, opens no draft', () => {
  const s = memory();
  assert.equal(readRunbookDraft(s), null);
  s.setItem('hearth.runbook.draft', '{not json');
  assert.equal(readRunbookDraft(s), null);
  s.setItem('hearth.runbook.draft', JSON.stringify({ yaml: '' }));
  assert.equal(readRunbookDraft(s), null);
});

test('the notice says who drafted it and what is left', () => {
  assert.match(runbookDraftNotice({ model: 'm', attempts: 2, valid: true, problems: [] }), /Drafted by m from a recorded terminal session \(2 tries\)\. Nothing is saved yet\. Review/);
  assert.match(runbookDraftNotice({ model: 'm', attempts: 1, valid: false, problems: [{}, {}] }), /2 problems\): fix them/);
});
