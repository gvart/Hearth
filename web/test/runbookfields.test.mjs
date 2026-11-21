// A runbook step as a form: fields read from the file, and edits that touch one value only. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { analyze } from '../src/runbookdoc.ts';
import { fieldsOf, moveStep, removeStep, setField } from '../src/runbookfields.ts';

const file = `# Heals Pi-hole.
id: heal-pihole
vars:
  box: pi5
steps:
  - id: restart   # the container
    type: action
    action:
      type: restart
      device: \${{ vars.box }}
      service: 'docker:pihole'
    timeout: 1m

  # Then make sure it answers.
  - id: answers
    type: check
    check: {type: http, url: "http://pi5.lan/admin", status: 200}
    within: 2m
  - id: script
    type: action
    action:
      type: exec
      device: pi5
      command:
        - /bin/sh
        - -c
        - |-
          set -eu
          echo "hello"
        - sh
`;

const diff = (a, b) => {
  const x = a.split('\n');
  const y = b.split('\n');
  return x.map((l, i) => (l === y[i] ? null : i + 1)).filter(Boolean);
};

test('fieldsOf lists a step\'s values in file order, with where they are', () => {
  assert.deepEqual(
    fieldsOf(file, 0).map((f) => `${f.path}=${f.value}`),
    ['id=restart', 'type=action', 'action.type=restart', 'action.device=${{ vars.box }}', 'action.service=docker:pihole', 'timeout=1m'],
  );
  const check = fieldsOf(file, 1);
  assert.deepEqual(check.find((f) => f.path === 'check.status'), {
    path: 'check.status',
    key: 'status',
    label: 'status',
    group: 'check',
    value: '200',
    kind: 'line',
  });
  const script = fieldsOf(file, 2);
  assert.deepEqual(
    script.filter((f) => f.key === 'command').map((f) => [f.label, f.kind, f.group]),
    [
      ['command 1', 'line', 'action'],
      ['command 2', 'line', 'action'],
      ['command 3', 'block', 'action'],
      ['command 4', 'line', 'action'],
    ],
  );
  assert.equal(script.find((f) => f.path === 'action.command.2').value, 'set -eu\necho "hello"');
  assert.deepEqual(fieldsOf(file, 9), []);
  assert.deepEqual(fieldsOf('steps: [', 0), []);
});

test('setField changes one value and no other byte', () => {
  const one = setField(file, 0, 'timeout', '90s');
  assert.deepEqual(diff(file, one), [12]);
  assert.match(one, /^ {4}timeout: 90s$/m);
  // The comment beside the id stays where it is.
  const renamed = setField(file, 0, 'id', 'bounce');
  assert.match(renamed, /^ {2}- id: bounce {3}# the container$/m);
  assert.deepEqual(diff(file, renamed), [6]);
  // A quoted value keeps its quotes; a flow map keeps its braces.
  assert.match(setField(file, 0, 'action.service', 'docker:unbound'), /service: 'docker:unbound'$/m);
  const flow = setField(file, 1, 'check.url', 'http://pi5.lan/health');
  assert.match(flow, /check: \{type: http, url: "http:\/\/pi5.lan\/health", status: 200\}/);
  assert.match(setField(file, 1, 'check.status', '204'), /status: 204\}/);
  // Space at the ends is not part of a value.
  assert.equal(setField(file, 0, 'timeout', '  90s '), one);
});

test('setField quotes what would not read back as the same value', () => {
  // A colon and a space would start a map; a hash would start a comment; a comma would end a flow value.
  assert.match(setField(file, 0, 'action.device', 'a: b'), /device: "a: b"$/m);
  assert.match(setField(file, 0, 'action.device', 'pi #5'), /device: "pi #5"$/m);
  assert.match(setField(file, 1, 'check.status', '200, 204'), /status: "200, 204"\}/);
  assert.match(setField(file, 0, 'action.device', ''), /device: ""$/m);
  assert.match(setField(file, 0, 'action.service', "it's"), /service: 'it''s'$/m);
  for (const text of [setField(file, 0, 'action.device', '[x'), setField(file, 0, 'action.device', '- x'), setField(file, 0, 'id', '{')]) {
    assert.equal(analyze(text, []).problems.filter((p) => /YAML|Map|Seq|flow/i.test(p.message)).length, 0);
    assert.equal(fieldsOf(text, 0).length, 6);
  }
});

test('setField rewrites a block under its own header and indent', () => {
  const out = setField(file, 2, 'action.command.2', 'set -eu\nsystemctl restart pihole\n\necho done\n\n');
  assert.equal(fieldsOf(out, 2).find((f) => f.path === 'action.command.2').value, 'set -eu\nsystemctl restart pihole\n\necho done');
  assert.match(out, /- \|-\n {10}set -eu\n {10}systemctl restart pihole\n\n {10}echo done\n {8}- sh\n$/);
  // Every line above the block is as it was.
  assert.equal(out.split('\n').slice(0, 26).join('\n'), file.split('\n').slice(0, 26).join('\n'));
  assert.match(setField(file, 2, 'action.command.2', ''), /- ""\n {8}- sh\n$/);
});

test('setField gives up on a path that is not there', () => {
  assert.equal(setField(file, 0, 'nope', 'x'), undefined);
  assert.equal(setField(file, 7, 'id', 'x'), undefined);
  assert.equal(setField('id: x', 0, 'id', 'y'), undefined);
});

test('removeStep cuts a step and nothing else', () => {
  const steps = analyze(file, []).steps;
  const out = removeStep(file, steps, 0);
  assert.deepEqual(analyze(out, []).steps.map((s) => s.id), ['answers', 'script']);
  assert.match(out, /steps:\n {2}# Then make sure it answers\.\n {2}- id: answers/);
  assert.ok(out.endsWith(file.slice(file.indexOf('  - id: answers'))));
  assert.deepEqual(analyze(removeStep(file, steps, 2), []).steps.map((s) => s.id), ['restart', 'answers']);
  assert.equal(removeStep(file, steps, 5), undefined);
  // A step that shares its line with "steps:" is not cut by guesswork.
  const flow = 'id: x\nsteps: [{id: a, type: wait, duration: 1s}, {id: b, type: wait, duration: 1s}]\n';
  assert.equal(removeStep(flow, analyze(flow, []).steps, 0), undefined);
});

test('moveStep swaps two neighbours and keeps what is between them', () => {
  const steps = analyze(file, []).steps;
  const down = moveStep(file, steps, 1, 1);
  assert.deepEqual(analyze(down, []).steps.map((s) => s.id), ['restart', 'script', 'answers']);
  assert.deepEqual(analyze(moveStep(file, steps, 1, -1), []).steps.map((s) => s.id), ['answers', 'restart', 'script']);
  assert.equal(down.split('\n').sort().join('\n'), file.split('\n').sort().join('\n'), 'the same lines, reordered');
  assert.equal(moveStep(file, steps, 0, -1), undefined);
  assert.equal(moveStep(file, steps, 2, 1), undefined);
  assert.equal(moveStep(down, analyze(down, []).steps, 2, -1), file);
});

test('every field of every recipe can be set to itself and to another value', () => {
  const dir = new URL('../../docs/recipes/runbooks/', import.meta.url);
  for (const name of readdirSync(dir).filter((f) => f.endsWith('.yaml'))) {
    const source = readFileSync(new URL(name, dir), 'utf8');
    const steps = analyze(source, []).steps;
    assert.ok(steps.length > 0, name);
    steps.forEach((_, i) => {
      for (const f of fieldsOf(source, i)) {
        assert.equal(setField(source, i, f.path, f.value), source, `${name} step ${String(i + 1)} ${f.path}: unchanged`);
        const changed = setField(source, i, f.path, 'changed');
        assert.ok(changed !== undefined, `${name} step ${String(i + 1)} ${f.path}: set`);
        assert.equal(fieldsOf(changed, i).find((x) => x.path === f.path).value, 'changed');
      }
    });
  }
});
