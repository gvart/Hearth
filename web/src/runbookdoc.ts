// What the runbook workbench knows about a runbook file while you type: its steps, its problems,
// the colours of its lines, the help for the line under the caret and the steps it can add.
// The hub has the last word (Check and plan); this is the instant feedback before it.
// Kept apart from the components so node --test can check it (web/test/runbookdoc.test.mjs).
// See docs/runbooks.md and docs/automations.md for the rules it mirrors.

import { isMap, isScalar, isSeq, LineCounter, parseDocument, type Node } from 'yaml';
import { allowsService } from './capabilities.ts';

export interface Problem {
  line: number;
  message: string;
  severity: 'error' | 'warning';
  /** The step it belongs to, or -1 for the file itself. */
  step: number;
}

export type StepTone = 'act' | 'check' | 'ask' | 'wait';

export type GuideKey =
  | 'file'
  | 'restart'
  | 'exec'
  | 'script'
  | 'webhook'
  | 'notify'
  | 'log'
  | 'action'
  | 'http'
  | 'tcp'
  | 'dns'
  | 'kube_node'
  | 'talos_node'
  | 'confirm'
  | 'input'
  | 'wait';

export interface StepInfo {
  id: string;
  guide: GuideKey;
  tone: StepTone;
  /** One line on what the step does, with vars filled in. */
  summary: string;
  line: number;
  endLine: number;
  /** A dangerous action: denied or held until the runbook is granted. */
  dangerous: boolean;
}

/** What a device's agent allows, as the hub reports it. */
export interface DeviceCeiling {
  /** The names a step may use for the device: its id, name and hostname. */
  names: string[];
  restart: string[];
  exec: string[];
  probe: boolean;
}

export interface Analysis {
  id: string;
  /** False when the file does not parse: the steps are then unknown. */
  parsed: boolean;
  steps: StepInfo[];
  vars: Record<string, string>;
  problems: Problem[];
}

type Plain = string | number | boolean | null | Plain[] | PlainMap;
interface PlainMap {
  [key: string]: Plain;
}

const isPlainMap = (v: Plain | undefined): v is PlainMap => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: Plain | undefined): string =>
  v === undefined || v === null || typeof v === 'object' ? '' : String(v);
const has = (o: PlainMap, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

const idPattern = /^[a-z0-9_-]+$/;
const durationPattern = /^(\d+(ms|s|m|h))+$/;
const varPattern = /\$\{\{\s*vars\.([A-Za-z0-9_-]+)\s*\}\}/g;

const knownActions = [
  'log',
  'webhook',
  'notify',
  'restart',
  'exec',
  'kube_restart',
  'kube_scale',
  'kube_delete_pod',
  'kube_cordon',
  'kube_uncordon',
  'kube_drain',
  'kube_node_delete',
  'plugin_command',
];
const dangerousActions = ['exec', 'kube_drain', 'kube_node_delete'];
const actionNeeds: Record<string, string[]> = {
  restart: ['device', 'service'],
  exec: ['device', 'command'],
  webhook: ['url'],
  notify: ['channel', 'message'],
  log: ['message'],
};
const checkNeeds: Record<string, string[]> = {
  http: ['url'],
  tcp: ['address'],
  dns: ['name'],
  kube_node: ['cluster', 'node'],
  talos_node: ['node'],
};
const stepFields: Record<string, string[]> = {
  action: ['action', 'rollback'],
  check: ['check', 'within', 'every'],
  prompt: ['prompt', 'message', 'secret', 'timeout'],
  wait: ['duration'],
};

const short = (t: string, n: number) => {
  const x = t.replace(/\s+/g, ' ').trim();
  return x.length > n ? `${x.slice(0, n - 1)}…` : x;
};

const isScript = (action: PlainMap) =>
  Array.isArray(action.command) && action.command[0] === '/bin/sh' && action.command[1] === '-c';

/**
 * Reads a runbook file: its steps with what each does, and the problems the hub
 * would refuse it for, plus what this hub's devices would not allow.
 */
export function analyze(source: string, devices: DeviceCeiling[]): Analysis {
  const counter = new LineCounter();
  const doc = parseDocument(source, { lineCounter: counter });
  const lineOf = (offset: number) => counter.linePos(offset).line;
  const lines = new WeakMap<PlainMap, Record<string, number>>();
  const problems: Problem[] = [];
  const once = new Set<string>();
  const add = (line: number, message: string, severity: Problem['severity'] = 'error', step = -1) => {
    const key = `${String(line)}${message}`;
    if (!once.has(key)) {
      once.add(key);
      problems.push({ line: Math.max(1, line), message, severity, step });
    }
  };
  for (const e of doc.errors) {
    add(
      e.linePos?.[0].line ?? 1,
      e.message.split('\n')[0]?.replace(/ at line \d+, column \d+:?$/, '') ?? 'This is not valid YAML.',
    );
  }

  /** The YAML tree as plain values, remembering the line of every key. */
  const plain = (node: Node | null | undefined): Plain => {
    if (isMap(node)) {
      const out: PlainMap = {};
      const at: Record<string, number> = {
        __start: node.range ? lineOf(node.range[0]) : 1,
      };
      for (const pair of node.items) {
        const key = isScalar(pair.key) ? String(pair.key.value) : '';
        if (key === '') {
          continue;
        }
        out[key] = plain(pair.value as Node | null);
        at[key] = isScalar(pair.key) && pair.key.range ? lineOf(pair.key.range[0]) : (at.__start ?? 1);
      }
      lines.set(out, at);
      return out;
    }
    if (isSeq(node)) {
      return node.items.map((item) => plain(item as Node | null));
    }
    if (isScalar(node)) {
      const v = node.value;
      // Anything else (a date, a binary blob) is nothing a runbook field holds.
      return typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? v : null;
    }
    return null;
  };
  const root = doc.errors.length === 0 ? plain(doc.contents) : null;
  const empty: Analysis = {
    id: '',
    parsed: false,
    steps: [],
    vars: {},
    problems,
  };
  if (!isPlainMap(root)) {
    if (problems.length === 0) {
      add(1, 'A runbook is a list of "key: value" lines, starting with id.');
    }
    return empty;
  }
  const at = (o: PlainMap, k: string) => lines.get(o)?.[k] ?? lines.get(o)?.__start ?? 1;

  for (const k of Object.keys(root)) {
    if (!['id', 'description', 'vars', 'steps'].includes(k)) {
      add(at(root, k), `Unknown field "${k}". A runbook has id, description, vars and steps.`);
    }
  }
  const id = text(root.id);
  if (id === '') {
    add(at(root, 'id'), 'Give the runbook an id, such as "id: restart-pihole".');
  } else if (!idPattern.test(id)) {
    add(at(root, 'id'), 'The id may hold lowercase letters, digits, - and _ only.');
  }

  const vars: Record<string, string> = {};
  if (root.vars !== undefined && root.vars !== null) {
    if (!isPlainMap(root.vars)) {
      add(at(root, 'vars'), 'vars is a list of "name: value" lines.');
    } else {
      for (const [k, v] of Object.entries(root.vars)) {
        vars[k] = text(v);
        if (!idPattern.test(k)) {
          add(at(root.vars, k), 'A var name may hold lowercase letters, digits, - and _ only.');
        }
        if (typeof v === 'object' && v !== null) {
          add(at(root.vars, k), 'A var holds one plain value.');
        } else if (text(v).includes('{{')) {
          add(at(root.vars, k), 'A var is a plain value: it cannot hold a template or another var.');
        }
      }
    }
  }
  const used = new Set<string>();
  source.split('\n').forEach((raw, i) => {
    if (/^\s*#/.test(raw)) {
      return;
    }
    let from = raw.indexOf('${{');
    while (from >= 0) {
      const m = /^\$\{\{\s*vars\.([A-Za-z0-9_-]+)\s*\}\}/.exec(raw.slice(from));
      if (!m?.[1]) {
        add(i + 1, 'Only ${{ vars.name }} can be filled in like this.');
        from = raw.indexOf('${{', from + 3);
        continue;
      }
      used.add(m[1]);
      if (!has(vars, m[1])) {
        add(i + 1, `The var "${m[1]}" is used here and is not declared under vars.`);
      }
      from = raw.indexOf('${{', from + m[0].length);
    }
  });
  if (isPlainMap(root.vars)) {
    for (const k of Object.keys(vars)) {
      if (!used.has(k)) {
        add(at(root.vars, k), `The var "${k}" is declared and never used. The hub refuses a file like that.`);
      }
    }
  }
  const fill = (v: Plain | undefined) => text(v).replace(varPattern, (whole, k: string) => vars[k] ?? whole);
  const deviceOf = (name: string) => devices.find((d) => d.names.includes(name));

  if (!Array.isArray(root.steps) || root.steps.length === 0) {
    add(at(root, 'steps'), 'Add at least one step under "steps:".');
    return { id, parsed: true, steps: [], vars, problems };
  }
  if (root.steps.length > 100) {
    add(at(root, 'steps'), 'A runbook has at most 100 steps.');
  }

  const total = source.split('\n').length;
  const seen = new Set<string>();
  const steps: StepInfo[] = root.steps.map((raw, i) => {
    const info: StepInfo = {
      id: '',
      guide: 'file',
      tone: 'wait',
      summary: 'a step with no type yet',
      line: at(root, 'steps'),
      endLine: total,
      dangerous: false,
    };
    if (!isPlainMap(raw)) {
      add(at(root, 'steps'), 'Each step starts with "- id: its-name".', 'error', i);
      return info;
    }
    const st = raw;
    const flag = (o: PlainMap, k: string, message: string, severity: Problem['severity'] = 'error') => {
      add(at(o, k), message, severity, i);
    };
    const duration = (o: PlainMap, k: string) => {
      if (o[k] !== undefined && o[k] !== null && !durationPattern.test(text(o[k]))) {
        flag(o, k, `"${k}" is a time such as 30s, 5m or 1h.`);
      }
    };
    info.line = lines.get(st)?.__start ?? info.line;
    info.id = text(st.id);
    if (info.id === '') {
      flag(st, 'id', 'This step needs an id.');
    } else {
      if (!idPattern.test(info.id)) {
        flag(st, 'id', 'A step id may hold lowercase letters, digits, - and _ only.');
      }
      if (seen.has(info.id)) {
        flag(st, 'id', `Two steps are called "${info.id}". Step ids are unique.`);
      }
      seen.add(info.id);
    }
    const type = text(st.type);
    const fields = stepFields[type];
    if (!fields) {
      flag(
        st,
        'type',
        type
          ? `"${type}" is not a step type. Use action, check, prompt or wait.`
          : 'This step needs a type: action, check, prompt or wait.',
      );
      return info;
    }
    for (const k of Object.keys(st)) {
      if (!['id', 'type', 'description', ...fields].includes(k)) {
        flag(st, k, `A ${type} step has no "${k}" field.`);
      }
    }
    const device = (o: PlainMap, k: string, need?: 'probe') => {
      const name = fill(o[k]);
      const dv = deviceOf(name);
      if (!dv) {
        if (!once.has(`dev:${name}`)) {
          once.add(`dev:${name}`);
          flag(
            o,
            k,
            `No device called "${name}" is enrolled on this hub. Steps that name it are denied until one is.`,
            'warning',
          );
        }
        return undefined;
      }
      if (need === 'probe' && !dv.probe) {
        flag(o, k, `${name}'s agent does not run checks. Turn Checks on in its Capabilities.`, 'warning');
      }
      return dv;
    };
    const action = (ac: PlainMap) => {
      const kind = text(ac.type);
      if (kind === 'script') {
        flag(ac, 'type', 'Scripts are for automations only. In a runbook, run a program on a device with exec.');
        return;
      }
      if (!knownActions.includes(kind)) {
        flag(
          ac,
          'type',
          kind
            ? `"${kind}" is not an action this editor knows.`
            : 'This action needs a type, such as restart, exec or webhook.',
          kind ? 'warning' : 'error',
        );
        return;
      }
      for (const k of actionNeeds[kind] ?? []) {
        if (ac[k] === undefined || ac[k] === null || ac[k] === '') {
          flag(ac, 'type', `A ${kind} action needs "${k}".`);
        }
      }
      duration(ac, 'timeout');
      if (kind === 'restart' && ac.service && !/^(systemd|systemd-user|docker):.+/.test(fill(ac.service))) {
        flag(ac, 'service', 'A service is systemd:UNIT, systemd-user:UNIT or docker:CONTAINER.');
      }
      if (kind === 'exec' && ac.command !== undefined && ac.command !== null) {
        if (!Array.isArray(ac.command)) {
          flag(
            ac,
            'command',
            'command is a list: the program, then each argument, such as [/usr/bin/df, -h]. It is never a shell line.',
          );
        } else if (ac.command.length === 0 || !ac.command[0]) {
          flag(ac, 'command', 'command needs at least the program to run.');
        }
      }
      if ((kind === 'restart' || kind === 'exec') && ac.device) {
        const dv = device(ac, 'device');
        const name = fill(ac.device);
        if (dv && kind === 'restart' && ac.service && !allowsService(dv.restart, fill(ac.service))) {
          flag(
            ac,
            'service',
            `${name}'s agent does not allow this restart. Turn Restart services on in its Capabilities.`,
            'warning',
          );
        }
        const program = Array.isArray(ac.command) ? fill(ac.command[0]) : '';
        if (dv && kind === 'exec' && program && !dv.exec.includes(program)) {
          flag(
            ac,
            'command',
            `${name}'s agent does not allow ${program}. Add it to Run programs in its Capabilities.`,
            'warning',
          );
        }
      }
    };

    if (type === 'wait') {
      info.guide = 'wait';
      info.summary = `waits ${text(st.duration)}`;
      if (st.duration === undefined || st.duration === null) {
        flag(st, 'duration', 'A wait step needs a duration, such as "duration: 30s".');
      }
      duration(st, 'duration');
    } else if (type === 'prompt') {
      info.tone = 'ask';
      info.guide = st.prompt === 'input' ? 'input' : 'confirm';
      info.summary = `${st.prompt === 'input' ? 'asks for text' : 'asks yes or no'}: ${short(fill(st.message), 40)}`;
      if (st.prompt !== 'confirm' && st.prompt !== 'input') {
        flag(st, 'prompt', 'prompt is "confirm" for yes or no, or "input" for a line of text.');
      }
      if (!st.message) {
        flag(st, 'message', 'A prompt needs a message: the question to ask.');
      }
      if (st.secret !== undefined && typeof st.secret !== 'boolean') {
        flag(st, 'secret', 'secret is true or false.');
      }
      duration(st, 'timeout');
    } else if (type === 'check') {
      info.tone = 'check';
      info.guide = 'http';
      info.summary = 'a check';
      const c = st.check;
      if (!isPlainMap(c)) {
        flag(st, 'check', 'A check step needs a check, such as "check: {type: tcp, address: 10.0.0.5:22}".');
      } else {
        const kind = text(c.type);
        const needs = checkNeeds[kind];
        if (!needs) {
          flag(c, 'type', 'A check is http, tcp, dns, kube_node or talos_node.');
        } else {
          info.guide = kind as GuideKey;
          info.summary =
            kind === 'http'
              ? `HTTP answers at ${short(fill(c.url), 30)}`
              : kind === 'tcp'
                ? `port open at ${fill(c.address)}`
                : kind === 'dns'
                  ? `DNS resolves ${fill(c.name)}`
                  : kind === 'kube_node'
                    ? `node ${fill(c.node)} is Ready`
                    : `Talos node ${fill(c.node)}${c.version ? ` runs ${fill(c.version)}` : ' is healthy'}`;
          for (const k of needs) {
            if (c[k] === undefined || c[k] === null || c[k] === '') {
              flag(c, 'type', `A ${kind} check needs "${k}".`);
            }
          }
          if (c.from !== undefined && c.from !== null) {
            if (kind === 'kube_node' || kind === 'talos_node') {
              flag(c, 'from', 'This check always runs from the hub: it has no "from".');
            } else {
              device(c, 'from', 'probe');
              info.summary += `, from ${fill(c.from)}`;
            }
          }
          duration(c, 'timeout');
        }
      }
      duration(st, 'within');
      duration(st, 'every');
    } else {
      info.tone = 'act';
      info.guide = 'action';
      info.summary = 'an action';
      const a = st.action;
      if (!isPlainMap(a)) {
        flag(st, 'action', 'An action step needs an action, such as a restart or a webhook.');
      } else {
        action(a);
        const kind = text(a.type);
        info.dangerous = dangerousActions.includes(kind);
        const command = Array.isArray(a.command) ? a.command.map((c) => fill(c)) : [];
        if (kind === 'restart') {
          info.guide = 'restart';
          info.summary = `restarts ${fill(a.service)} on ${fill(a.device)}`;
        } else if (kind === 'exec') {
          info.guide = isScript(a) ? 'script' : 'exec';
          info.summary = `runs ${isScript(a) ? 'a script' : short(`${(command[0] ?? '').split('/').pop() ?? ''} ${command.slice(1).join(' ')}`, 28)} on ${fill(a.device)}`;
        } else if (kind === 'webhook') {
          info.guide = 'webhook';
          info.summary = `calls ${short(fill(a.url).replace(/^https?:\/\//, ''), 32)}`;
        } else if (kind === 'notify') {
          info.guide = 'notify';
          info.summary = `notifies ${fill(a.channel)}`;
        } else if (kind === 'log') {
          info.guide = 'log';
          info.summary = 'writes a log line';
        } else {
          info.summary = kind.replace(/_/g, ' ') || 'an action';
        }
      }
      if (st.rollback !== undefined && st.rollback !== null) {
        if (!isPlainMap(st.rollback)) {
          flag(st, 'rollback', 'rollback is another action, which undoes this one.');
        } else {
          action(st.rollback);
          info.summary += ' · can undo';
        }
      }
    }
    return info;
  });

  // Each step runs to the line before the next one; trailing blank lines belong to nobody.
  const source_lines = source.split('\n');
  steps.forEach((s, i) => {
    let end = (steps[i + 1]?.line ?? total + 1) - 1;
    while (end > s.line && (source_lines[end - 1] ?? '').trim() === '') {
      end--;
    }
    s.endLine = Math.max(s.line, end);
  });
  for (const p of problems) {
    if (p.step < 0) {
      p.step = steps.findIndex((s) => p.line >= s.line && p.line <= s.endLine);
    }
  }
  problems.sort((a, b) => (a.severity === b.severity ? a.line - b.line : a.severity === 'error' ? -1 : 1));
  return { id, parsed: true, steps, vars, problems };
}

/** The step a line belongs to, or -1 for the file's own lines. */
export function stepAt(steps: StepInfo[], line: number): number {
  return steps.findIndex((s) => line >= s.line && line <= s.endLine);
}

export type TokenClass = 'y-val' | 'y-str' | 'y-num' | 'y-kw' | 'y-type' | 'y-var';

/** One line of the file, cut into the pieces that take a colour. */
export interface HighlightLine {
  indent: string;
  dash: string;
  key: string;
  sep: string;
  parts: { text: string; cls: TokenClass }[];
  comment: string;
}

function commentAt(s: string): number {
  let quote = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i);
    if (quote) {
      if (c === quote) {
        quote = '';
      }
    } else if ((c === '"' || c === "'") && (i === 0 || /[\s:[{,-]/.test(s.charAt(i - 1)))) {
      quote = c;
    } else if (c === '#' && (i === 0 || /\s/.test(s.charAt(i - 1)))) {
      return i;
    }
  }
  return -1;
}

/** Colours for a file, line by line. It reads the text only, so it works on a file that does not parse. */
export function highlight(source: string): HighlightLine[] {
  let blockIndent = -1;
  return source.split('\n').map((raw) => {
    const indent = /^ */.exec(raw)?.[0].length ?? 0;
    const out: HighlightLine = {
      indent: '',
      dash: '',
      key: '',
      sep: '',
      parts: [],
      comment: '',
    };
    let cls: TokenClass = 'y-val';
    let value: string;
    if (blockIndent >= 0 && (raw.trim() === '' || indent > blockIndent)) {
      // Inside a block of text (after | or >): everything is the text, # included.
      cls = 'y-str';
      value = raw;
    } else {
      blockIndent = -1;
      const m = /^(\s*)(-\s+|-$)?(.*)$/.exec(raw);
      out.indent = m?.[1] ?? '';
      out.dash = m?.[2] ?? '';
      let rest = m?.[3] ?? '';
      if (rest.startsWith('#')) {
        out.comment = rest;
        rest = '';
      } else {
        const km = /^([^\s:#"'[{][^:]*?|"[^"]*"|'[^']*')(\s*:)(\s+|$)(.*)$/.exec(rest);
        if (km) {
          out.key = km[1] ?? '';
          out.sep = (km[2] ?? '') + (km[3] ?? '');
          rest = km[4] ?? '';
        }
        const ci = commentAt(rest);
        if (ci >= 0) {
          out.comment = rest.slice(ci);
          rest = rest.slice(0, ci);
        }
        const t = rest.trim();
        if (/^[|>][+-]?$/.test(t)) {
          cls = 'y-kw';
          blockIndent = indent;
        } else if (/^["']/.test(t)) {
          cls = 'y-str';
        } else if (/^(true|false|null)$/.test(t)) {
          cls = 'y-kw';
        } else if (/^-?\d+(\.\d+)?(ms|s|m|h)?$/.test(t)) {
          cls = 'y-num';
        } else if (out.key === 'type' || out.key === 'prompt') {
          cls = 'y-type';
        }
      }
      value = rest;
    }
    // Values a file fills in, ${{ vars.x }} and {{ .Input.x }}, stand out wherever they are.
    value.split(/(\$?\{\{[^}]*\}\})/).forEach((piece, i) => {
      if (piece !== '') {
        out.parts.push({ text: piece, cls: i % 2 === 1 ? 'y-var' : cls });
      }
    });
    return out;
  });
}

const keyDocs: Record<string, string> = {
  id: 'A name: lowercase letters, digits, - and _. The runbook id names the file. A step id is unique in it.',
  description: 'One line that says what this does. Shown in the list, the plan and the run.',
  vars: 'Values the steps repeat, named once. Use one as ${{ vars.name }}.',
  steps: 'What happens, in order. At most 100.',
  action: 'What an action step does: restart, exec, webhook, notify or log.',
  rollback: 'Another action, which undoes this step when you roll a stopped run back.',
  check: 'What a check step waits for: http, tcp, dns, kube_node or talos_node.',
  within: 'How long to keep trying before the step fails, such as 2m.',
  every: 'How often to try again, such as 5s.',
  prompt: 'confirm asks yes or no. input asks for a line of text.',
  message: 'The question a prompt asks, or the text a log or notify action sends.',
  secret: 'true for a password or token: the answer is never stored, logged or shown.',
  timeout: 'How long to wait before giving up. A prompt: 1h, at most 7 days. An action: 1m, at most 10m.',
  duration: 'How long a wait step pauses. At most 24h.',
  device: 'The device it runs on: its id, name or hostname.',
  service: 'What to restart: systemd:UNIT, systemd-user:UNIT or docker:CONTAINER.',
  command: "A list: the program, then each argument. Never a shell line. The device's agent must allow the program.",
  url: 'Where a webhook is sent, or what an http check asks.',
  method: 'The HTTP method. POST unless you say otherwise.',
  headers: 'HTTP headers, as {Name: value}.',
  body: 'The request body. It may use a prompt answer, as {{ .Input.step-id }}.',
  channel: 'A notification channel of this hub.',
  title: 'An optional title for the notification.',
  cluster: 'A Kubernetes cluster, by its name on the Platforms page.',
  node: 'The node to check: its name for Kubernetes, its address for Talos.',
  name: 'The DNS name to look up.',
  server: 'Which DNS server to ask.',
  address: 'host:port to connect to.',
  version: 'The Talos version the node must run.',
  healthy: 'true: every service on the node must be healthy.',
  status: 'The HTTP status the URL must answer with.',
  from: 'A device to run the check from, instead of the hub.',
};

/** What a key of a runbook file means, in one line; undefined for a key the reference does not name. */
export function docOf(key: string): string | undefined {
  return keyDocs[key];
}

/** One line of help for the line the caret is on: the key it sets, and what that means. */
export function keyHelp(
  lines: HighlightLine[],
  line: number,
  vars: Record<string, string>,
): { key: string; text: string } | undefined {
  const depth = (l: HighlightLine) => l.indent.length + l.dash.length;
  let i = line - 1;
  let cur = lines[i];
  if (!cur) {
    return undefined;
  }
  if (cur.key === '') {
    // A list item or a line of a text block: the help is for the key above that owns it.
    const d = cur.indent === '' && cur.dash === '' && cur.parts[0]?.cls === 'y-str' ? Infinity : depth(cur);
    for (i -= 1; i >= 0; i--) {
      const l = lines[i];
      if (l && l.key !== '' && depth(l) < d) {
        break;
      }
    }
    cur = lines[i];
  }
  if (!cur || cur.key === '') {
    return undefined;
  }
  const key = cur.key;
  const doc =
    key === 'type'
      ? depth(cur) <= 4
        ? 'The kind of step: action, check, prompt or wait.'
        : 'What to do or to check: restart, exec, webhook, notify, log, or http, tcp, dns, kube_node, talos_node.'
      : depth(cur) === 2 && has(vars, key)
        ? `A var. Use it in any step as \${{ vars.${key} }}.`
        : keyDocs[key];
  return doc ? { key, text: doc } : undefined;
}

export interface Snippet {
  key: string;
  group: 'Do something' | 'Check the result' | 'Ask a person' | 'Pause';
  tone: StepTone;
  label: string;
  hint: string;
  /** The step's id, made unique when it is added. */
  id: string;
  /** The step's lines after its id, indented as they sit in the file. */
  body: string[];
}

/** The steps the workbench can add, each a short, valid starting point. */
export const snippets: Snippet[] = [
  {
    key: 'restart',
    group: 'Do something',
    tone: 'act',
    label: 'Restart a service',
    hint: 'A systemd unit or a Docker container',
    id: 'restart',
    body: ['type: action', 'action:', '  type: restart', '  device: DEVICE', '  service: docker:NAME'],
  },
  {
    key: 'exec',
    group: 'Do something',
    tone: 'act',
    label: 'Run a command',
    hint: 'A program, or your own script file, on a device',
    id: 'run',
    body: ['type: action', 'action:', '  type: exec', '  device: DEVICE', '  command: [/usr/local/bin/your-script.sh]'],
  },
  {
    key: 'script',
    group: 'Do something',
    tone: 'act',
    label: 'Run a script',
    hint: 'A shell script you write right here',
    id: 'script',
    body: [
      'type: action',
      'action:',
      '  type: exec',
      '  device: DEVICE',
      '  command:',
      '    - /bin/sh',
      '    - -c',
      '    - |-',
      '      set -eu',
      '      echo "hello from $1"',
      '    - sh',
      '    - the-runbook',
    ],
  },
  {
    key: 'webhook',
    group: 'Do something',
    tone: 'act',
    label: 'Call a webhook',
    hint: 'One HTTP request from the hub',
    id: 'call',
    body: ['type: action', 'action:', '  type: webhook', '  url: http://host.lan:8080/path'],
  },
  {
    key: 'notify',
    group: 'Do something',
    tone: 'act',
    label: 'Notify me',
    hint: 'A message to a notification channel',
    id: 'tell',
    body: ['type: action', 'action:', '  type: notify', '  channel: CHANNEL', '  message: Done.'],
  },
  {
    key: 'http',
    group: 'Check the result',
    tone: 'check',
    label: 'HTTP answers',
    hint: 'Wait until a URL responds',
    id: 'healthy',
    body: [
      'type: check',
      'check: {type: http, url: "http://host.lan:8080/health", status: 200}',
      'within: 2m',
      'every: 5s',
    ],
  },
  {
    key: 'tcp',
    group: 'Check the result',
    tone: 'check',
    label: 'A port is open',
    hint: 'Wait until host:port accepts a connection',
    id: 'port-open',
    body: ['type: check', 'check: {type: tcp, address: "10.0.0.5:22"}', 'within: 1m', 'every: 5s'],
  },
  {
    key: 'dns',
    group: 'Check the result',
    tone: 'check',
    label: 'DNS resolves',
    hint: 'Wait until a name answers',
    id: 'dns-answers',
    body: ['type: check', 'check: {type: dns, name: example.com}', 'within: 2m'],
  },
  {
    key: 'kube_node',
    group: 'Check the result',
    tone: 'check',
    label: 'Kubernetes node is Ready',
    hint: 'In a cluster the hub has adopted',
    id: 'node-ready',
    body: ['type: check', 'check: {type: kube_node, cluster: CLUSTER, node: NODE}', 'within: 15m', 'every: 15s'],
  },
  {
    key: 'talos_node',
    group: 'Check the result',
    tone: 'check',
    label: 'Talos node is healthy',
    hint: 'Read through the Talos API',
    id: 'node-healthy',
    body: ['type: check', 'check: {type: talos_node, node: 10.0.0.12, healthy: true}', 'within: 20m', 'every: 15s'],
  },
  {
    key: 'confirm',
    group: 'Ask a person',
    tone: 'ask',
    label: 'Yes or no',
    hint: 'Stop until someone says go',
    id: 'go-ahead',
    body: ['type: prompt', 'prompt: confirm', 'message: Go ahead?'],
  },
  {
    key: 'input',
    group: 'Ask a person',
    tone: 'ask',
    label: 'A line of text',
    hint: 'A reason, a version, a password',
    id: 'reason',
    body: ['type: prompt', 'prompt: input', 'message: Why is this happening?'],
  },
  {
    key: 'wait',
    group: 'Pause',
    tone: 'wait',
    label: 'Wait',
    hint: 'Let things settle for a set time',
    id: 'settle',
    body: ['type: wait', 'duration: 30s'],
  },
];

/**
 * Adds a step after step `after` (or at the end for -1), as text: nothing else
 * in the file changes. Returns the new text and the line the step starts on.
 */
export function insertStep(
  source: string,
  a: Analysis,
  after: number,
  snippet: Snippet,
): { text: string; line: number } {
  let id = snippet.id;
  for (let n = 2; a.steps.some((s) => s.id === id); n++) {
    id = `${snippet.id}-${String(n)}`;
  }
  const block = [`  - id: ${id}`, ...snippet.body.map((l) => `    ${l}`)];
  const lines = source.replace(/\n+$/, '').split('\n');
  const anchor = a.steps[after] ?? a.steps[a.steps.length - 1];
  if (!anchor) {
    // No steps yet: start the list, unless the file already has an empty "steps:".
    const head = lines.some((l) => /^steps:\s*$/.test(l)) ? [] : ['steps:'];
    const text = [...lines, ...head, ...block].join('\n');
    return { text: `${text}\n`, line: lines.length + head.length + 1 };
  }
  const at = anchor.endLine;
  const text = [...lines.slice(0, at), '', ...block, ...lines.slice(at)].join('\n');
  return { text: `${text}\n`, line: at + 2 };
}

export interface GuideEntry {
  title: string;
  lead: string;
  policy?: 'read' | 'safe' | 'dangerous';
  fields: [string, string][];
  notes: string[];
}

const grant =
  'Dangerous. A runbook acts as automation/runbook/<id>, and policy denies it dangerous actions until you grant them: add runbook/<id> to dangerous_automations in the policy.';

/** What the guide says about the file and about each kind of step. */
export const guide: Record<GuideKey, GuideEntry> = {
  file: {
    title: 'The runbook file',
    lead: 'One file. Its steps run top to bottom. A step that fails stops the run, and you then retry that step or roll back the ones that finished.',
    fields: [
      ['id', 'Its name. Required.'],
      ['description', 'One line for the list.'],
      ['vars', 'Values the steps repeat, named once.'],
      ['steps', 'What happens, in order. At most 100.'],
    ],
    notes: ['Nothing runs while you edit. "Check and plan" asks the hub what it would do, and still runs nothing.'],
  },
  restart: {
    title: 'Restart a service',
    lead: 'Restarts one systemd unit or Docker container on a device.',
    policy: 'safe',
    fields: [
      ['device', 'Its id, name or hostname.'],
      ['service', 'systemd:UNIT, systemd-user:UNIT or docker:CONTAINER.'],
      ['timeout', 'Optional: 1m, at most 10m.'],
    ],
    notes: [
      'The device has the last word. Its agent restarts only what Restart services allows in its Capabilities.',
    ],
  },
  exec: {
    title: 'Run a command',
    lead: 'Runs one program on a device, with its arguments. This is how a runbook runs your own script: keep it as a file on the device and name its path.',
    policy: 'dangerous',
    fields: [
      ['device', 'Where it runs.'],
      ['command', 'A list: the program, then each argument. Never a shell line.'],
      ['timeout', 'Optional: 1m, at most 10m.'],
    ],
    notes: [
      'Allow the program first: add its path, such as /usr/local/bin/backup.sh, to Run programs in the device\'s Capabilities. The path must match exactly.',
      grant,
      'The step fails when the program exits with a non-zero code.',
    ],
  },
  script: {
    title: 'Run a script',
    lead: 'Runs a shell script written in the file, through /bin/sh -c on a device.',
    policy: 'dangerous',
    fields: [
      ['command', '/bin/sh, -c, the script, sh, then its arguments.'],
      ['$1 $2', 'The arguments after "sh".'],
      ['timeout', 'Optional: 1m, at most 10m.'],
    ],
    notes: [
      'The agent must allow /bin/sh, and an agent that may run sh may run anything. Take /bin/sh out of Run programs again after the run, or keep the script as a file and allow only that file.',
      grant,
    ],
  },
  webhook: {
    title: 'Call a webhook',
    lead: 'Sends one HTTP request from the hub.',
    policy: 'safe',
    fields: [
      ['url', 'Where to send it. Not a template.'],
      ['method', 'POST unless you say otherwise.'],
      ['headers', 'Optional, as {Name: value}.'],
      ['body', 'Optional text.'],
      ['timeout', 'Optional: 10s, at most 1m.'],
    ],
    notes: ['The body and header values may use a prompt answer, as {{ .Input.step-id }}.'],
  },
  notify: {
    title: 'Notify me',
    lead: "Sends a message to one of this hub's notification channels.",
    policy: 'safe',
    fields: [
      ['channel', 'A channel from the Notifications page.'],
      ['title', 'Optional.'],
      ['message', 'The text.'],
    ],
    notes: [],
  },
  log: {
    title: 'Write a log line',
    lead: 'Writes one line to the hub log. Useful as a last step that says what was done.',
    policy: 'read',
    fields: [['message', 'The text.']],
    notes: [],
  },
  action: {
    title: 'An action',
    lead: 'An action from the automation reference: Kubernetes restarts, scaling, cordon and drain, or a plugin command.',
    fields: [],
    notes: ['See docs/automations.md for their fields.'],
  },
  http: {
    title: 'Check: HTTP answers',
    lead: 'Passes when the URL answers. Tried again and again until it passes or time runs out.',
    policy: 'read',
    fields: [
      ['url', 'What to ask.'],
      ['status', 'Optional: the status it must answer with.'],
      ['from', 'Optional: a device to ask from.'],
      ['within', 'How long to keep trying.'],
      ['every', 'How often.'],
    ],
    notes: [
      'Put a check after every action that can go wrong. It is what turns a list of commands into a runbook you can trust.',
    ],
  },
  tcp: {
    title: 'Check: a port is open',
    lead: 'Passes when something accepts a connection on host:port.',
    policy: 'read',
    fields: [
      ['address', 'host:port.'],
      ['from', 'Optional: a device to try from.'],
      ['within', 'How long to keep trying.'],
      ['every', 'How often.'],
    ],
    notes: ['From a device, Checks must be on in its Capabilities.'],
  },
  dns: {
    title: 'Check: DNS resolves',
    lead: 'Passes when the name resolves.',
    policy: 'read',
    fields: [
      ['name', 'The name to look up.'],
      ['server', 'Optional: which DNS server to ask.'],
      ['within', 'How long to keep trying.'],
    ],
    notes: [],
  },
  kube_node: {
    title: 'Check: Kubernetes node is Ready',
    lead: 'Passes when the node is Ready in a cluster the hub has adopted.',
    policy: 'read',
    fields: [
      ['cluster', 'Its name in Hearth.'],
      ['node', "The node's name."],
      ['within', 'How long to keep trying.'],
    ],
    notes: ['A node that is not there yet counts as not Ready, so the step keeps waiting while a new node joins.'],
  },
  talos_node: {
    title: 'Check: Talos node is healthy',
    lead: 'Reads a Talos node through the Talos API.',
    policy: 'read',
    fields: [
      ['node', 'Its address or hostname.'],
      ['version', 'Optional: the version it must run.'],
      ['healthy', 'true: every service must be healthy.'],
      ['within', 'How long to keep trying.'],
    ],
    notes: [],
  },
  confirm: {
    title: 'Ask yes or no',
    lead: 'Stops and asks you yes or no. Use it before anything you cannot take back.',
    fields: [
      ['message', 'The question.'],
      ['timeout', 'Optional: 1h, at most 7 days.'],
    ],
    notes: ['No fails the step, and the run stops there.'],
  },
  input: {
    title: 'Ask for a line of text',
    lead: 'Stops and asks for one line of text.',
    fields: [
      ['message', 'The question.'],
      ['secret', 'true for a password or token.'],
      ['timeout', 'Optional: 1h, at most 7 days.'],
    ],
    notes: [
      'An answer is data: it can fill a webhook body or a message as {{ .Input.step-id }}, and it can never name a device or a command.',
    ],
  },
  wait: {
    title: 'Wait',
    lead: 'Pauses the run.',
    fields: [['duration', 'Such as 30s or 5m. At most 24h.']],
    notes: [],
  },
};
