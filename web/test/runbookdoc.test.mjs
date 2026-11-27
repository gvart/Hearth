// The runbook workbench's reading of a file. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { analyze, guide, highlight, insertStep, keyHelp, snippets, stepAt } from '../src/runbookdoc.ts';

const pi5 = {
  names: ['d2', 'pi5', 'pi5.lan'],
  restart: ['docker:pihole'],
  exec: ['/usr/bin/df'],
  probe: true,
};
const starter = `# Restart Pi-hole.
id: restart-pihole
description: Restart Pi-hole on pi5 and check that DNS answers again.
vars:
  device: pi5
steps:
  - id: go-ahead
    type: prompt
    prompt: confirm
    message: Restart Pi-hole on \${{ vars.device }} now?

  - id: restart
    type: action
    action:
      type: restart
      device: \${{ vars.device }}
      service: docker:pihole

  - id: dns-answers
    type: check
    check: {type: dns, name: example.com, server: 192.168.20.171}
    within: 2m
`;
const errors = (src, devices = [pi5]) =>
  analyze(src, devices).problems.map((p) => `${p.severity} L${p.line} ${p.message}`);

test('the recipes in docs/recipes/runbooks have no errors', () => {
  const dir = new URL('../../docs/recipes/runbooks/', import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith('.yaml'));
  assert.ok(files.length >= 4);
  for (const f of files) {
    const a = analyze(readFileSync(new URL(f, dir), 'utf8'), []);
    assert.deepEqual(
      a.problems.filter((p) => p.severity === 'error'),
      [],
      f,
    );
    assert.ok(a.parsed && a.steps.length >= 5, f);
    // The only thing to say about them here is that their device is not enrolled.
    assert.ok(
      a.problems.every((p) => p.message.startsWith('No device called')),
      f,
    );
  }
});

test('a valid file has its steps, in order, with what each does', () => {
  const a = analyze(starter, [pi5]);
  assert.deepEqual(a.problems, []);
  assert.equal(a.id, 'restart-pihole');
  assert.deepEqual(a.vars, { device: 'pi5' });
  assert.deepEqual(
    a.steps.map((s) => [s.id, s.tone, s.guide, s.summary, s.line, s.endLine]),
    [
      ['go-ahead', 'ask', 'confirm', 'asks yes or no: Restart Pi-hole on pi5 now?', 7, 10],
      ['restart', 'act', 'restart', 'restarts docker:pihole on pi5', 12, 17],
      ['dns-answers', 'check', 'dns', 'DNS resolves example.com', 19, 22],
    ],
  );
  assert.equal(stepAt(a.steps, 15), 1);
  assert.equal(stepAt(a.steps, 3), -1);
});

test('problems the hub would refuse a file for, each on its line', () => {
  const cases = [
    [
      starter.replace('type: prompt', 'type: prmpt'),
      'error L8 "prmpt" is not a step type. Use action, check, prompt or wait.',
    ],
    [starter.replace('within: 2m', 'within: soon'), 'error L22 "within" is a time such as 30s, 5m or 1h.'],
    [
      starter.replace('id: restart-pihole', 'id: Restart Pihole'),
      'error L2 The id may hold lowercase letters, digits, - and _ only.',
    ],
    [
      starter.replace('  - id: restart\n', '  - id: go-ahead\n'),
      'error L12 Two steps are called "go-ahead". Step ids are unique.',
    ],
    [starter.replace('      service: docker:pihole\n', ''), 'error L15 A restart action needs "service".'],
    [
      starter.replace('  device: pi5\n', '  device: pi5\n  spare: x\n'),
      'error L6 The var "spare" is declared and never used. The hub refuses a file like that.',
    ],
    [
      starter.replace('vars.device }} now', 'vars.host }} now'),
      'error L10 The var "host" is used here and is not declared under vars.',
    ],
    [
      starter.replace('type: restart', 'type: script'),
      'error L15 Scripts are for automations only. In a runbook, run a program on a device with exec.',
    ],
    [
      starter.replace('    message: Restart', '    question: Restart'),
      'error L10 A prompt step has no "question" field.',
    ],
  ];
  for (const [src, want] of cases) {
    assert.ok(errors(src).includes(want), `${want}\n  got: ${errors(src).join('\n       ')}`);
  }
});

test('a file that is not YAML says where, and has no steps', () => {
  const a = analyze(starter.replace('steps:', 'steps'), [pi5]);
  assert.equal(a.parsed, false);
  assert.deepEqual(a.steps, []);
  assert.equal(a.problems.length > 0 && a.problems.every((p) => p.severity === 'error'), true);
  assert.ok(a.problems[0].line >= 6 && a.problems[0].line <= 8, String(a.problems[0].line));
});

test('what a device does not allow is a warning, not an error', () => {
  assert.deepEqual(errors(starter.replace('docker:pihole', 'docker:jellyfin')), [
    "warning L17 pi5's agent does not allow this restart. Turn Restart services on in its Capabilities.",
  ]);
  assert.deepEqual(errors(starter, []), [
    'warning L16 No device called "pi5" is enrolled on this hub. Steps that name it are denied until one is.',
  ]);
  const exec = starter
    .replace('type: restart', 'type: exec')
    .replace('service: docker:pihole', 'command: [/bin/sh, -c, "echo hi"]');
  assert.deepEqual(errors(exec), [
    "warning L17 pi5's agent does not allow /bin/sh. Add it to Run programs in its Capabilities.",
  ]);
  const a = analyze(exec, [pi5]);
  assert.equal(a.steps[1].dangerous, true);
  assert.equal(a.steps[1].guide, 'script');
});

test('highlight colours keys, values, vars, comments and text blocks', () => {
  const lines = highlight(
    '# note\nid: x  # the name\n  - id: go\n    type: prompt\n    within: 2m\n    device: ${{ vars.device }}:22\n    script: |-\n      echo "# not a comment"\n    secret: true',
  );
  assert.deepEqual(lines[0], {
    indent: '',
    dash: '',
    key: '',
    sep: '',
    parts: [],
    comment: '# note',
  });
  assert.deepEqual(
    [lines[1].key, lines[1].sep, lines[1].parts, lines[1].comment],
    ['id', ': ', [{ text: 'x  ', cls: 'y-val' }], '# the name'],
  );
  assert.deepEqual([lines[2].indent, lines[2].dash, lines[2].key], ['  ', '- ', 'id']);
  assert.equal(lines[3].parts[0].cls, 'y-type');
  assert.equal(lines[4].parts[0].cls, 'y-num');
  assert.deepEqual(lines[5].parts, [
    { text: '${{ vars.device }}', cls: 'y-var' },
    { text: ':22', cls: 'y-val' },
  ]);
  assert.equal(lines[6].parts[0].cls, 'y-kw');
  assert.deepEqual(lines[7], {
    indent: '',
    dash: '',
    key: '',
    sep: '',
    parts: [{ text: '      echo "# not a comment"', cls: 'y-str' }],
    comment: '',
  });
  assert.equal(lines[8].parts[0].cls, 'y-kw');
  // Every line gives back exactly its text.
  for (const [i, raw] of starter.split('\n').entries()) {
    const l = highlight(starter)[i];
    assert.equal(l.indent + l.dash + l.key + l.sep + l.parts.map((p) => p.text).join('') + l.comment, raw);
  }
});

test('keyHelp explains the key on a line, or the key that owns it', () => {
  const lines = highlight(starter);
  const help = (n) => keyHelp(lines, n, { device: 'pi5' });
  assert.equal(help(1), undefined);
  assert.equal(help(2).key, 'id');
  assert.match(help(5).text, /^A var\. Use it in any step as \$\{\{ vars\.device \}\}/);
  assert.equal(help(8).text, 'The kind of step: action, check, prompt or wait.');
  assert.match(help(15).text, /^What to do or to check/);
  assert.equal(help(17).key, 'service');
  assert.equal(help(21).key, 'check');
});

test('insertStep adds a step as text, with an id of its own, and the file still passes', () => {
  const a = analyze(starter, [pi5]);
  const wait = snippets.find((s) => s.key === 'wait');
  const after = insertStep(starter, a, 1, wait);
  assert.equal(after.text.split('\n')[after.line - 1], '  - id: settle');
  const b = analyze(after.text, [pi5]);
  assert.deepEqual(b.problems, []);
  assert.deepEqual(
    b.steps.map((s) => s.id),
    ['go-ahead', 'restart', 'settle', 'dns-answers'],
  );
  // Everything that was there is still there, in order.
  assert.deepEqual(
    after.text.split('\n').filter((l) => !['', '  - id: settle', '    type: wait', '    duration: 30s'].includes(l)),
    starter.split('\n').filter((l) => l !== ''),
  );
  const again = insertStep(after.text, b, -1, wait);
  assert.deepEqual(
    analyze(again.text, [pi5])
      .steps.map((s) => s.id)
      .slice(-1),
    ['settle-2'],
  );
  const fresh = insertStep('id: x\n', analyze('id: x\n', []), -1, wait);
  assert.equal(fresh.text, 'id: x\nsteps:\n  - id: settle\n    type: wait\n    duration: 30s\n');
});

test('every snippet is a step the checks accept, and has a guide entry', () => {
  for (const s of snippets) {
    const r = insertStep('id: x\n', analyze('id: x\n', []), -1, s);
    const a = analyze(r.text, []);
    assert.deepEqual(
      a.problems.filter((p) => p.severity === 'error'),
      [],
      s.key,
    );
    assert.equal(a.steps.length, 1, s.key);
    assert.equal(a.steps[0].tone, s.tone, s.key);
    assert.ok(guide[a.steps[0].guide].title, s.key);
  }
});
