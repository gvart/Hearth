// Round-trips every example automation in the repository through the visual
// editor's model. Run with `npm test` in web/. With HEARTH_BIN set to a hearth
// binary, the hub's own parser also compares each complete example's plan.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, test } from 'node:test';
import { isPair, parseDocument, visit } from 'yaml';
import {
  addStep,
  moveStep,
  readAutomation,
  removeStep,
  setField,
  setKey,
  stepSpecs,
  writeBack,
} from '../src/automations/model.ts';

const repo = new URL('../../', import.meta.url).pathname;

/** Every automation in the docs (whole files and fragments) and the built-ins. */
function examples() {
  const out = [];
  const docs = join(repo, 'docs');
  for (const name of readdirSync(docs).filter((f) => f.endsWith('.md'))) {
    const text = readFileSync(join(docs, name), 'utf8');
    let n = 0;
    for (const m of text.matchAll(/^( *)```yaml\n([\s\S]*?)^ *```$/gm)) {
      n += 1;
      const body = m[2].replace(new RegExp(`^${m[1]}`, 'gm'), '');
      if (/^(triggers|conditions|actions):/m.test(body)) {
        out.push({ name: `docs/${name}#${String(n)}`, source: body });
      }
    }
  }
  const go = readFileSync(join(repo, 'internal/automation/newdevice.go'), 'utf8');
  const builtin = /newDeviceAlertsYAML = `([\s\S]*?)`/.exec(go);
  assert.ok(builtin, 'the built-in automation was not found');
  out.push({ name: 'built-in new-device-alerts', source: builtin[1].replace('CHANNEL', 'phone') });
  return out;
}

/** Every comment, with the path of the node it is attached to. */
function commentsOf(source) {
  const doc = parseDocument(source);
  const out = [];
  const note = (where, node) => {
    for (const side of ['commentBefore', 'comment']) {
      if (node[side]) {
        out.push(`${where} ${side}: ${node[side]}`);
      }
    }
  };
  note('document', doc);
  visit(doc, (key, node, path) => {
    if (isPair(node)) {
      return;
    }
    const where = [...path.filter((p) => isPair(p)).map((p) => p.key.value), String(key)].join('.');
    note(where, node);
  });
  return out;
}

/** Every key of every mapping, in file order. */
function keysOf(source) {
  const out = [];
  visit(parseDocument(source), {
    Pair(_, pair) {
      out.push(String(pair.key.value));
    },
  });
  return out;
}

const valueOf = (source) => parseDocument(source).toJS();

const readOnlyParts = (model) => [
  ...model.extras,
  ...Object.values(model.rawSections),
  ...Object.values(model.blocks).flatMap((blocks) =>
    blocks.flatMap((b) => (b.kind === 'raw' ? [b] : b.extras)),
  ),
];

const all = examples();

// What the visual editor shows read-only, by example. Everything else in every
// example has a form field. A new entry here must be a deliberate decision.
const expectedReadOnly = {};

describe('every example automation', () => {
  test('there are examples to test', () => {
    assert.ok(all.length >= 13, `only ${String(all.length)} examples found`);
    assert.ok(all.some((e) => e.name.startsWith('built-in')));
  });

  for (const { name, source } of all) {
    describe(name, () => {
      test('reads into the visual model', () => {
        const read = readAutomation(source);
        assert.ok(read.ok, JSON.stringify(read.problems));
        const readOnly = readOnlyParts(read.model).map((p) => p.yaml);
        assert.deepEqual(readOnly, expectedReadOnly[name] ?? []);
      });

      test('writes back with the same meaning, comments and key order', () => {
        const written = writeBack(source);
        assert.deepEqual(valueOf(written), valueOf(source));
        assert.deepEqual(commentsOf(written), commentsOf(source));
        assert.deepEqual(keysOf(written), keysOf(source));
      });

      test('writes back byte for byte', () => {
        assert.equal(writeBack(source), source);
      });

      test('reads the same model after writing back', () => {
        assert.deepEqual(readAutomation(writeBack(source)), readAutomation(source));
      });

      test('an edit leaves every other line, comment and key as it was', () => {
        const written = setKey(source, null, 'description', 'Edited by the round-trip test');
        const others = (text) => text.split('\n').filter((line) => !line.startsWith('description:'));
        const keys = (text) => keysOf(text).filter((key) => key !== 'description');
        assert.equal(valueOf(written).description, 'Edited by the round-trip test');
        assert.deepEqual(others(written), others(source));
        assert.deepEqual(keys(written), keys(source));
        assert.deepEqual(commentsOf(written), commentsOf(source));
      });
    });
  }
});

describe('the hub reads the written file as the original', { skip: !process.env.HEARTH_BIN }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'hearth-roundtrip-'));
  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });
  const plan = (file, content) => {
    const path = join(dir, file);
    writeFileSync(path, content);
    return execFileSync(process.env.HEARTH_BIN, ['automation', 'plan', path], { encoding: 'utf8' }).replace(path, 'FILE');
  };
  const complete = all.filter(({ source }) => /^id:/m.test(source) && /^triggers:/m.test(source) && /^actions:/m.test(source));

  test('some examples are complete automations', () => {
    assert.ok(complete.length >= 3);
  });
  for (const { name, source } of complete) {
    test(name, () => {
      assert.equal(plan('written.yaml', writeBack(source)), plan('original.yaml', source));
    });
  }
});

const commented = `# Top of the file.
id: lights   # the id

# Why this exists.
description: "Quoted stays quoted"
mode: queued
triggers:
  # Before the first trigger.
  - id: nightly          # aligned comment
    type: schedule
    cron: "0 3 * * *"    # at three
  - {id: flow, type: device, to: offline}

actions:
  - id: call
    type: webhook
    url: https://example.com/hook   # secret goes here
    headers: {Title: "{{ .Trigger.ID }}", X-Other: kept}
    body: |
      line one
        line two
  # Between the actions.
  - id: note
    type: log
    message: hi
    retries: 3   # a key the hub does not know
`;

describe('editing keeps everything else', () => {
  const unchangedExcept = (written, changedLine) => {
    const before = commented.split('\n');
    const after = written.split('\n');
    assert.equal(after.length, before.length);
    const different = before.flatMap((line, i) => (line === after[i] ? [] : [i + 1]));
    assert.deepEqual(different, [changedLine]);
  };

  test('changing one field changes one line', () => {
    const http = stepSpecs.actions.webhook.fields.find((f) => f.key === 'url');
    const written = setField(commented, { section: 'actions', index: 0 }, http, 'https://example.com/other');
    unchangedExcept(written, 17);
    const column = (text) => text.split('\n').find((l) => l.includes('# secret')).indexOf('#');
    assert.match(written, /url: https:\/\/example\.com\/other +# secret goes here/);
    assert.equal(column(written), column(commented));
  });

  test('a scalar keeps its quotes', () => {
    const written = setKey(commented, null, 'description', 'Changed');
    unchangedExcept(written, 5);
    assert.match(written, /^description: "Changed"$/m);
  });

  test('a templated value is quoted so that it stays a string', () => {
    const message = stepSpecs.actions.log.fields[0];
    const written = setField(commented, { section: 'actions', index: 1 }, message, '{{ .Trigger.ID }}');
    assert.equal(valueOf(written).actions[1].message, '{{ .Trigger.ID }}');
  });

  test('a value only different in spaces is not lost', () => {
    const message = stepSpecs.actions.log.fields[0];
    const one = setField(commented, { section: 'actions', index: 1 }, message, 'a  b');
    const two = setField(one, { section: 'actions', index: 1 }, message, 'a b');
    assert.equal(valueOf(two).actions[1].message, 'a b');
  });

  test('a number stays a number', () => {
    const source = 'id: a\ntriggers:\n  - type: metric\n    above: 90   # percent\nactions: []\n';
    const above = stepSpecs.triggers.metric.fields.find((f) => f.key === 'above');
    const written = setField(source, { section: 'triggers', index: 0 }, above, '85.5');
    assert.equal(valueOf(written).triggers[0].above, 85.5);
    assert.match(written, /# percent/);
  });

  test('a key the form cannot show survives and is shown read-only', () => {
    const read = readAutomation(commented);
    assert.ok(read.ok);
    const note = read.model.blocks.actions[1];
    assert.deepEqual(note.extras.map((e) => e.yaml), ['retries: 3']);
    const written = setKey(commented, { section: 'actions', index: 1 }, 'id', 'renamed');
    assert.equal(valueOf(written).actions[1].retries, 3);
    assert.match(written, /retries: 3 {3}# a key the hub does not know/);
  });

  test('moving a step keeps its comments and every other step', () => {
    const written = moveStep(commented, 'actions', 0, 1);
    assert.deepEqual(valueOf(written).actions.map((a) => a.id), ['note', 'call']);
    assert.deepEqual([...commentsOf(written)].sort().length, commentsOf(commented).length);
    assert.match(written, /# secret goes here/);
    assert.deepEqual(valueOf(moveStep(written, 'actions', 0, 1)), valueOf(commented));
  });

  test('adding and removing a step leaves the others alone', () => {
    const added = addStep(commented, 'triggers', 'manual');
    assert.equal(valueOf(added).triggers.length, 3);
    assert.deepEqual(valueOf(removeStep(added, 'triggers', 2)), valueOf(commented));
    assert.match(removeStep(added, 'triggers', 2), /# at three/);
  });

  test('a missing section is added before the actions', () => {
    const written = addStep('id: a\nactions:\n  - type: log\n    message: hi\n', 'triggers', 'manual');
    assert.deepEqual(Object.keys(valueOf(written)), ['id', 'triggers', 'actions']);
  });
});

describe('what the form cannot represent stays intact and visible', () => {
  const cases = [
    ['an anchor', 'id: a\ntriggers:\n  - &t\n    type: manual\nactions: []\n', 'triggers'],
    ['a merge key', 'id: a\nx: &d {message: hi}\nactions:\n  - <<: *d\n    type: log\n', 'actions'],
    ['an alias step', 'id: a\nx: &s {type: manual}\ntriggers:\n  - *s\nactions: []\n', 'triggers'],
    ['a custom tag', 'id: a\ntriggers:\n  - !custom {type: manual}\nactions: []\n', 'triggers'],
    ['an unknown step type', 'id: a\nactions:\n  - type: future\n    knob: 1 # note\n', 'actions'],
    ['a condition', 'id: a\nconditions:\n  - type: time\n    after: "08:00"\n', 'conditions'],
    ['a step that is no mapping', 'id: a\ntriggers:\n  - just text\nactions: []\n', 'triggers'],
  ];
  for (const [name, source, section] of cases) {
    test(name, () => {
      const read = readAutomation(source);
      assert.ok(read.ok, JSON.stringify(read.problems));
      assert.equal(read.model.blocks[section][0].kind, 'raw');
      assert.ok(read.model.blocks[section][0].reason);
      const written = setKey(source, null, 'description', 'edited');
      assert.deepEqual({ ...valueOf(written), description: undefined }, { ...valueOf(source), description: undefined });
      assert.equal(valueOf(written).description, 'edited');
    });
  }

  test('a value of the wrong shape is shown read-only, not lost', () => {
    const source = 'id: a\ntriggers:\n  - type: network\n    batch: yes\nactions: []\n';
    const read = readAutomation(source);
    assert.ok(read.ok);
    const [block] = read.model.blocks.triggers;
    assert.equal(block.values.batch, undefined);
    assert.deepEqual(block.extras.map((e) => e.yaml), ['batch: yes']);
    assert.match(setKey(source, { section: 'triggers', index: 0 }, 'id', 'x'), /batch: yes/);
  });

  test('an alias used as a whole section is read-only', () => {
    const source = 'id: a\nt: &t [{type: manual}]\ntriggers: *t\nactions: []\n';
    const read = readAutomation(source);
    assert.ok(read.ok);
    assert.ok(read.model.rawSections.triggers);
  });

  test('a file that does not parse is refused with its line', () => {
    const read = readAutomation('id: a\ntriggers: [\n');
    assert.equal(read.ok, false);
    assert.ok(read.problems[0].line >= 2);
  });

  test('a file of several documents is refused rather than cut short', () => {
    assert.equal(readAutomation('id: a\n---\nid: b\n').ok, false);
  });
});
