// Files the visual view could misread open in the YAML view only. The hub reads
// U+0085, U+2028 and U+2029 as line breaks and this editor's parser does not, so
// a step can hide inside what the form shows as a comment or a single value.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import * as model from '../src/automations/model.ts';
import * as session from '../src/automations/session.ts';

const plain = `id: plain
triggers:
  - type: manual
actions:
  - type: log
    message: hello
`;

const hiddenBreaks = [
  ['U+0085', '\u0085'],
  ['U+2028', '\u2028'],
  ['U+2029', '\u2029'],
];

const messageField = model.stepSpecs.actions.log.fields.find((f) => f.key === 'message');
const logRef = { section: 'actions', index: 0 };

describe('a file holding a character the hub reads as a line break', () => {
  for (const [name, char] of hiddenBreaks) {
    const hidden = `id: hidden
triggers:
  - type: manual
actions:
  - type: log
    message: hello # note${char}  - type: exec${char}    device: pi4${char}    command: [/bin/rm, /data]
`;

    test(`${name} opens in the YAML view only`, () => {
      const read = model.readAutomation(hidden);
      assert.equal(read.ok, false);
      assert.equal(read.yamlOnly, true);
      assert.match(model.yamlOnlyReason(hidden), new RegExp(name.replace('+', '\\+')));
    });

    test(`${name} cannot be edited through the form`, () => {
      assert.throws(() => model.setKey(hidden, null, 'description', 'x'), /YAML/);
      assert.throws(() => model.removeStep(hidden, 'actions', 0), /YAML/);
    });

    test(`${name} is refused in form input`, () => {
      assert.throws(() => model.setKey(plain, null, 'description', `a${char}b`), /line break/);
      assert.throws(() => model.setField(plain, logRef, messageField, `a${char}b`), /line break/);
      const list = { key: 'command', label: 'Command', kind: 'list' };
      assert.throws(() => model.setField(plain, logRef, list, ['ok', `a${char}b`]), /line break/);
      const map = { key: 'headers', label: 'Headers', kind: 'map' };
      assert.throws(() => model.setField(plain, logRef, map, [['X', `a${char}b`]]), /line break/);
      assert.throws(() => model.setField(plain, logRef, map, [[`a${char}b`, 'x']]), /line break/);
    });
  }

  test('an escape the hub reads as text inside quotes stays read-only and blocks nothing else', () => {
    const escaped = plain.replace('message: hello', 'message: "a\\u2028b"');
    assert.equal(model.yamlOnlyReason(escaped), undefined);
    const read = model.readAutomation(escaped);
    assert.equal(read.ok, true);
    const step = read.model.blocks.actions[0];
    assert.equal(step.values.message, undefined);
    assert.equal(step.extras.length, 1);
    const edited = model.setKey(escaped, null, 'description', 'fine');
    assert.match(edited, /message: "a\\u2028b"/);
  });

  test('a file without them opens as usual', () => {
    assert.equal(model.yamlOnlyReason(plain), undefined);
    assert.equal(model.readAutomation(plain).ok, true);
  });
});

describe('a file repeating an anchor name', () => {
  const repeated = `id: anchors
triggers:
  - type: manual
actions:
  - id: first
    type: exec
    device: &target pi4
    command: [/bin/true]
  - id: second
    type: exec
    device: &target nas
    command: [/bin/true]
  - id: third
    type: exec
    device: *target
    command: [/bin/rm, /data]
`;

  test('opens in the YAML view only, naming the anchor', () => {
    const read = model.readAutomation(repeated);
    assert.equal(read.ok, false);
    assert.equal(read.yamlOnly, true);
    assert.match(model.yamlOnlyReason(repeated), /&target/);
  });

  test('cannot have its steps moved or removed', () => {
    assert.throws(() => model.moveStep(repeated, 'actions', 1, -1), /YAML/);
    assert.throws(() => model.removeStep(repeated, 'actions', 1), /YAML/);
  });

  test('an anchor used once still opens visually, read-only', () => {
    const once = repeated.replace('device: &target nas', 'device: nas');
    assert.equal(model.yamlOnlyReason(once), undefined);
    assert.equal(model.readAutomation(once).ok, true);
  });
});

describe('what the editor says around a save', () => {
  test('a saved file whose audit entry failed says both', () => {
    const notice = session.savedNotice({
      file: 'a.yaml',
      hub: 'hub:8443',
      cluster: false,
      leader: true,
      warning: 'The audit log did not record how this save ended.',
    });
    assert.match(notice, /^Saved to a\.yaml/);
    assert.match(notice, /audit log/);
  });

  test('an approval link says the plan is withheld', () => {
    const { planText, planWithheld, rest } = session.approvalDetail({ file: 'a.yaml', plan_withheld: true });
    assert.equal(planText, '');
    assert.equal(planWithheld, true);
    assert.deepEqual(rest, { file: 'a.yaml' });
  });
});
