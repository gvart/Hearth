// A visual edit must leave every value nobody touched exactly as the hub reads
// it. These values are the ones a JavaScript reader changes: each comparison
// here uses the hub's own YAML parser, through internal/automation/testdata.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import {
  addStep,
  moveStep,
  readAutomation,
  removeStep,
  setField,
  setKey,
  stepSpecs,
} from '../src/automations/model.ts';
import { approvalDetail, mayEdit, savedNotice } from '../src/automations/session.ts';

const repo = new URL('../../', import.meta.url).pathname;

const precise = `# Values a JavaScript reader would change.
id: precise
description: before
triggers:
  - type: manual
actions:
  - id: scale
    type: kube_scale
    replicas: 010
  - id: call
    type: webhook
    url: https://example.com/hook
    headers:
      X-Api-Key: 00123456789012345678901234
  - id: chmod
    type: exec
    device: pi4
    command: [chmod, 0750, /tmp/x]
  - id: tell
    type: notify
    channel: 007
    title: +4915112345678
    message: hi
  - id: big
    type: log
    message: 9007199254740993
`;

let dir;
let hubread;

before(() => {
  dir = mkdtempSync(join(tmpdir(), 'hearth-values-'));
  hubread = join(dir, 'hubread');
  execFileSync('go', ['build', '-o', hubread, './internal/automation/testdata/hubread'], { cwd: repo });
});

after(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** What the hub's parser reads: the top-level keys, each with its tree. */
function hubReads(source) {
  const doc = JSON.parse(execFileSync(hubread, { input: source, encoding: 'utf8' }));
  const root = doc.content[0].content;
  const out = {};
  for (let i = 0; i + 1 < root.length; i += 2) {
    out[root[i].value] = root[i + 1];
  }
  return out;
}

/** The hub's reading of one action, found by its id. */
function hubStep(source, id) {
  return hubReads(source).actions.content.find((step) =>
    step.content.some((n, i) => i % 2 === 1 && step.content[i - 1].value === 'id' && n.value === id),
  );
}

const stepIds = ['scale', 'call', 'chmod', 'tell', 'big'];

function assertStepsUnchanged(written, ids = stepIds) {
  for (const id of ids) {
    assert.deepEqual(hubStep(written, id), hubStep(precise, id), `step ${id} changed for the hub`);
  }
}

describe('values nobody touched stay what the hub reads', () => {
  test('editing the description', () => {
    const written = setKey(precise, null, 'description', 'after');
    assertStepsUnchanged(written);
    assert.equal(hubReads(written).description.value, 'after');
    assert.equal(written, precise.replace('description: before', 'description: after'));
  });

  for (const [text, why] of [
    ['replicas: 010', 'octal 8, not 10'],
    ['X-Api-Key: 00123456789012345678901234', 'a key, not 1.23e+23'],
    ['command: [chmod, 0750, /tmp/x]', 'the mode 0750, not 750'],
    ['channel: 007', 'not 7'],
    ['title: +4915112345678', 'keeps its plus'],
    ['message: 9007199254740993', 'beyond a double'],
  ]) {
    test(`${text} survives (${why})`, () => {
      assert.ok(setKey(precise, null, 'description', 'after').includes(text));
      assert.ok(setKey(precise, { section: 'actions', index: 0 }, 'description', 'note').includes(text));
      assert.ok(addStep(precise, 'triggers', 'manual').includes(text));
    });
  }

  test('editing another step', () => {
    const written = setKey(precise, { section: 'actions', index: 0 }, 'id', 'renamed');
    assertStepsUnchanged(written, ['call', 'chmod', 'tell', 'big']);
  });

  test('adding a step', () => {
    assertStepsUnchanged(addStep(precise, 'actions', 'log'));
  });

  test('removing a step', () => {
    assertStepsUnchanged(removeStep(precise, 'actions', 0), ['call', 'chmod', 'tell', 'big']);
  });

  test('moving a step', () => {
    const written = moveStep(precise, 'actions', 1, 1);
    assertStepsUnchanged(written);
    const ids = hubReads(written).actions.content.map((s) => s.content[1].value);
    assert.deepEqual(ids, ['scale', 'chmod', 'call', 'tell', 'big']);
  });

  test('those values are shown read-only, never in an input', () => {
    const read = readAutomation(precise);
    assert.ok(read.ok);
    const [, call, chmod, tell] = read.model.blocks.actions;
    assert.equal(call.values.headers, undefined);
    assert.equal(chmod.values.command, undefined);
    assert.equal(tell.values.channel, undefined);
    assert.equal(tell.values.title, undefined);
  });

  test('a block text at the end of a file with no final newline reads as the hub reads it', () => {
    const head = 'id: a\nactions:\n  - type: webhook\n    url: https://e.example\n    body: ';
    for (const [style, tail, want] of [
      ['|', '\n      a', 'a'],
      ['|', '\n      a\n', 'a\n'],
      ['|-', '\n      a', 'a'],
      ['|+', '\n      a', 'a'],
      ['|+', '\n      a\n', 'a\n'],
      ['>', '\n      a', 'a'],
      ['>', '\n      a\n', 'a\n'],
    ]) {
      const source = head + style + tail;
      const hub = hubReads(source).actions.content[0].content.find((n, i, all) => all[i - 1]?.value === 'body').value;
      assert.equal(hub, want, `hub reads ${JSON.stringify(source)}`);
      const read = readAutomation(source);
      assert.ok(read.ok);
      assert.equal(read.model.blocks.actions[0].values.body, hub, `editor reads ${JSON.stringify(source)}`);
    }
  });

  test('a number the hub reads differently is read-only', () => {
    const source = 'id: a\ntriggers:\n  - type: metric\n    above: 010\nactions: []\n';
    const read = readAutomation(source);
    assert.ok(read.ok);
    assert.equal(read.model.blocks.triggers[0].values.above, undefined);
  });

  test('a new value that looks like a number stays a string for the hub', () => {
    const message = stepSpecs.actions.log.fields[0];
    const written = setField(precise, { section: 'actions', index: 4 }, message, '0750');
    const step = hubStep(written, 'big');
    const value = step.content[step.content.findIndex((n) => n.value === 'message') + 1];
    assert.equal(value.value, '0750');
    assert.equal(value.tag, '!!str');
  });

  for (const word of ['yes', 'no', 'on', 'off', 'null', '~', 'true', '1e3', '0x10', '1_000']) {
    test(`"${word}" typed into a text field reaches the hub as that text`, () => {
      const written = setKey(precise, null, 'description', word);
      const description = hubReads(written).description;
      assert.equal(description.value, word);
      assert.equal(description.tag, '!!str');
    });
  }
});

describe('lists and maps are edited item by item', () => {
  const list = stepSpecs.actions.exec.fields.find((f) => f.key === 'command');
  const headers = stepSpecs.actions.webhook.fields.find((f) => f.key === 'headers');
  const ref = { section: 'actions', index: 0 };

  test('values lines would change are shown read-only', () => {
    const source = 'id: a\nactions:\n  - type: exec\n    device: d\n    command: [printf, "  padded  ", " ", /tmp/x]\n';
    const read = readAutomation(source);
    assert.ok(read.ok);
    assert.equal(read.model.blocks.actions[0].values.command, undefined);
    assert.deepEqual(read.model.blocks.actions[0].extras.map((e) => e.yaml), [
      'command: [printf, "  padded  ", " ", /tmp/x]',
    ]);
  });

  test('a header with padding is shown read-only', () => {
    const source = 'id: a\nactions:\n  - type: webhook\n    url: https://e.example\n    headers: {A: " b "}\n';
    const read = readAutomation(source);
    assert.ok(read.ok);
    assert.equal(read.model.blocks.actions[0].values.headers, undefined);
  });

  test('changing one item of a flow list keeps the others as written', () => {
    const source = `id: a\nactions:\n  - type: exec\n    device: d\n    command: [a, "b", 'c', d]\n`;
    const written = setField(source, ref, list, ['a', 'x', 'c', 'd']);
    assert.match(written, /command: \[a, "x", 'c', d\]/);
  });

  test('changing one item of a block list changes one line', () => {
    const source = 'id: a\nactions:\n  - type: exec\n    device: d\n    command:\n      - a   # first\n      - "b"\n';
    const written = setField(source, ref, list, ['a', 'z']);
    assert.equal(written, source.replace('- "b"', '- "z"'));
  });

  test('adding and removing items of a block list', () => {
    const source = 'id: a\nactions:\n  - type: exec\n    device: d\n    command:\n      - a\n      - b\n';
    assert.equal(setField(source, ref, list, ['a', 'b', 'c']), `${source}      - c\n`);
    assert.equal(setField(source, ref, list, ['a']), source.replace('      - b\n', ''));
  });

  test('changing one header keeps the others as written', () => {
    const source = 'id: a\nactions:\n  - type: webhook\n    url: https://e.example\n    headers:\n      A: "1"   # one\n      B: two\n';
    const written = setField(source, ref, headers, [['A', '1'], ['B', 'three']]);
    assert.equal(written, source.replace('B: two', 'B: three'));
  });

  test('a flow mapping gains and loses a key without rewriting the rest', () => {
    const source = 'id: a\ntriggers:\n  - {id: flow, type: device, to: "offline"}\nactions: []\n';
    const noted = setKey(source, { section: 'triggers', index: 0 }, 'description', 'note');
    assert.match(noted, /to: "offline"/);
    assert.equal(readAutomation(noted).model.blocks.triggers[0].description, 'note');
    const cleared = setKey(noted, { section: 'triggers', index: 0 }, 'description', '');
    assert.equal(cleared, source);
  });
});

describe('structure edits touch only their own lines', () => {
  const body = stepSpecs.actions.webhook.fields.find((f) => f.key === 'body');
  const ref = { section: 'actions', index: 0 };
  const hook = 'id: a\nactions:\n  - type: webhook\n    url: https://e.example\n';

  test('a block text is replaced as a block text', () => {
    const source = `${hook}    body: |\n      one\n        two\n    timeout: 5s\n`;
    const written = setField(source, ref, body, 'three\n  four\n');
    assert.equal(written, `${hook}    body: |\n      three\n        four\n    timeout: 5s\n`);
  });

  test('a one-line text can become several lines and back', () => {
    const source = `${hook}    body: one\n    timeout: 5s\n`;
    const written = setField(source, ref, body, 'one\ntwo');
    assert.equal(hubReads(written).actions.content[0].content[5].value, 'one\ntwo');
    assert.equal(setField(written, ref, body, 'one'), source);
  });

  test('removing the last step leaves an empty list the hub can read', () => {
    const source = 'id: a\ntriggers:\n  - type: manual\nactions:\n  - type: log\n    message: hi\n';
    const written = removeStep(source, 'triggers', 0);
    assert.equal(written, 'id: a\ntriggers: []\nactions:\n  - type: log\n    message: hi\n');
    assert.equal(addStep(written, 'triggers', 'manual'), source);
  });

  test('moving the last step of a file with no final newline', () => {
    const source = 'id: a\nactions:\n  - type: log\n    message: one\n  - type: log\n    message: two';
    const written = moveStep(source, 'actions', 1, -1);
    assert.equal(written, 'id: a\nactions:\n  - type: log\n    message: two\n  - type: log\n    message: one');
  });

  test('steps written in flow style are added, moved and removed in place', () => {
    const source = 'id: a\ntriggers: [{type: manual}, {id: "b", type: manual}]\nactions: []\n';
    assert.match(addStep(source, 'triggers', 'manual'), /\[\{type: manual\}, \{id: "b", type: manual\}, \{type: manual\}\]/);
    assert.match(moveStep(source, 'triggers', 0, 1), /\[\{id: "b", type: manual\}, \{type: manual\}\]/);
    assert.match(removeStep(source, 'triggers', 0), /triggers: \[\{id: "b", type: manual\}\]/);
  });

  test('a step added to an empty section', () => {
    const written = addStep('id: a\ntriggers: []   # none yet\nactions: []\n', 'triggers', 'manual');
    assert.equal(readAutomation(written).model.blocks.triggers.length, 1);
  });

  test('a comment on its own line survives removing the step above it', () => {
    const source = 'id: a\nactions:\n  - type: log\n    message: one\n  # keep me\n  - type: log\n    message: two\n';
    assert.match(removeStep(source, 'actions', 0), /# keep me/);
  });
});

describe('what cannot be spliced safely is refused', () => {
  test('a flow list over several lines points to the YAML view', () => {
    const list = stepSpecs.actions.exec.fields.find((f) => f.key === 'command');
    const source = 'id: a\nactions:\n  - type: exec\n    device: d\n    command: [a, # why\n      b]\n';
    assert.throws(
      () => setField(source, { section: 'actions', index: 0 }, list, ['a', 'b', 'c']),
      /YAML view/,
    );
  });

  test('removing the only key of a step is refused rather than guessed', () => {
    const source = 'id: a\ntriggers:\n  - description: only\nactions: []\n';
    assert.throws(() => setKey(source, { section: 'triggers', index: 0 }, 'description', ''), /YAML view/);
  });
});

describe('while a save is pending', () => {
  test('the form is locked', () => {
    assert.equal(mayEdit(true), false);
    assert.equal(mayEdit(false), true);
  });
});

describe('what an approver reads', () => {
  test('the plan is text of its own, apart from the other details', () => {
    const plan = 'Automation a\n  1. run ["/bin/sh"] on pi4\n';
    const { planText, rest } = approvalDetail({ file: 'a.yaml', plan });
    assert.equal(planText, plan);
    assert.deepEqual(rest, { file: 'a.yaml' });
  });

  test('details without a plan stay as they are', () => {
    assert.deepEqual(approvalDetail({ file: 'a.yaml' }), { planText: '', rest: { file: 'a.yaml' } });
    assert.deepEqual(approvalDetail({ plan: 3 }), { planText: '', rest: { plan: 3 } });
  });
});

describe('the notice after saving', () => {
  const saved = { id: 'a', file: 'a.yaml', revision: 'r', hub: 'hub-b:8443' };

  test('a single hub loads the file itself', () => {
    const notice = savedNotice({ ...saved, cluster: false, leader: true });
    assert.equal(notice, 'Saved to a.yaml. The hub loads it within seconds.');
  });

  test('a cluster leader names itself and the other hubs', () => {
    const notice = savedNotice({ ...saved, cluster: true, leader: true });
    assert.match(notice, /hub-b:8443/);
    assert.match(notice, /copy/i);
    assert.doesNotMatch(notice, /loads it within seconds\.$/);
  });

  test('a stored automation is on every hub', () => {
    const notice = savedNotice({ ...saved, cluster: true, leader: false, stored: true });
    assert.match(notice, /Every hub/);
    assert.doesNotMatch(notice, /copy/i);
  });

  test('a cluster follower says the file does not run from here', () => {
    const notice = savedNotice({ ...saved, cluster: true, leader: false });
    assert.match(notice, /hub-b:8443/);
    assert.match(notice, /leader/);
    assert.match(notice, /copy/i);
    assert.doesNotMatch(notice, /within seconds/);
  });
});
