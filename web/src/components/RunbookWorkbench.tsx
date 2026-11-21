import { useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { useDevices } from '../api/hooks.ts';
import {
  analyze,
  guide,
  highlight,
  insertStep,
  keyHelp,
  snippets,
  stepAt,
  type DeviceCeiling,
  type Snippet,
  type StepTone,
} from '../runbookdoc.ts';
import './RunbookWorkbench.css';

const toneWord: Record<StepTone, string> = {
  act: 'acts',
  check: 'checks',
  ask: 'asks you',
  wait: 'waits',
};
const groups = ['Do something', 'Check the result', 'Ask a person', 'Pause'] as const;

/**
 * The runbook file as a workbench: its steps down the left, the file itself
 * with colours, line numbers and problems marked as you type, a line of help
 * for the key under the caret, steps to add, and a guide on demand.
 */
export default function RunbookWorkbench({
  value,
  invalid,
  onChange,
}: {
  value: string;
  invalid: boolean;
  onChange: (value: string) => void;
}) {
  const devices = useDevices().data;
  const ceilings = useMemo<DeviceCeiling[]>(
    () =>
      (devices ?? []).map((d) => ({
        names: [d.id, d.name, d.hostname].filter(Boolean),
        restart: d.facts.ceiling?.restart ?? [],
        exec: d.facts.ceiling?.exec ?? [],
        probe: d.facts.ceiling?.probe ?? false,
      })),
    [devices],
  );
  const a = useMemo(() => analyze(value, ceilings), [value, ceilings]);
  const lines = useMemo(() => highlight(value), [value]);
  const [line, setLine] = useState(0);
  const [adding, setAdding] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);
  const area = useRef<HTMLTextAreaElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  // Where the caret goes once an edit made here (a new step, Tab, Enter) has rendered.
  const caret = useRef<{ at: number; reveal: boolean }>(undefined);
  const guideId = useId();

  const selected = line > 0 ? stepAt(a.steps, line) : -1;
  const step = a.steps[selected];
  const entry = guide[step?.guide ?? 'file'];
  const help = keyHelp(lines, line, a.vars);
  const errors = a.problems.filter((p) => p.severity === 'error').length;
  const warnings = a.problems.length - errors;
  const worst = new Map<number, 'error' | 'warning'>();
  for (const p of a.problems) {
    if (worst.get(p.line) !== 'error') {
      worst.set(p.line, p.severity);
    }
  }

  useLayoutEffect(() => {
    const el = area.current;
    const c = caret.current;
    if (!el || !c) {
      return;
    }
    caret.current = undefined;
    el.focus();
    el.setSelectionRange(c.at, c.at);
    if (c.reveal && scroller.current) {
      const lineHeight = parseFloat(getComputedStyle(el).lineHeight) || 20;
      const n = el.value.slice(0, c.at).split('\n').length;
      scroller.current.scrollTop = Math.max(0, (n - 4) * lineHeight);
    }
  }, [value]);

  /** Puts the caret at the start of a line and brings it into view. */
  const goTo = (n: number) => {
    const el = area.current;
    if (!el) {
      return;
    }
    const at =
      value
        .split('\n')
        .slice(0, n - 1)
        .join('\n').length + (n > 1 ? 1 : 0);
    el.focus();
    el.setSelectionRange(at, at);
    setLine(n);
    if (scroller.current) {
      const lineHeight = parseFloat(getComputedStyle(el).lineHeight) || 20;
      scroller.current.scrollTop = Math.max(0, (n - 4) * lineHeight);
    }
  };

  const add = (s: Snippet) => {
    const r = insertStep(value, a, selected, s);
    const at =
      r.text
        .split('\n')
        .slice(0, r.line - 1)
        .join('\n').length + 1;
    caret.current = { at, reveal: true };
    setLine(r.line);
    setAdding(false);
    onChange(r.text);
  };

  const readCaret = () => {
    const el = area.current;
    if (el) {
      setLine(el.value.slice(0, el.selectionStart).split('\n').length);
    }
  };

  // Tab indents by two spaces; Enter keeps the indent, and deepens it after "key:" or "- ".
  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.key !== 'Tab' || e.shiftKey) && e.key !== 'Enter') {
      return;
    }
    const el = e.currentTarget;
    const from = el.selectionStart;
    let insert = '  ';
    if (e.key === 'Enter') {
      const current = el.value.slice(el.value.lastIndexOf('\n', from - 1) + 1, from);
      const indent = /^ */.exec(current)?.[0] ?? '';
      insert = `\n${indent}${/:\s*$/.test(current) || /^\s*- /.test(current) ? '  ' : ''}`;
    }
    e.preventDefault();
    caret.current = { at: from + insert.length, reveal: false };
    onChange(el.value.slice(0, from) + insert + el.value.slice(el.selectionEnd));
    setLine(el.value.slice(0, from).split('\n').length + (e.key === 'Enter' ? 1 : 0));
  };

  return (
    <div className="wb">
      <div className="wb-bar">
        <span className={`pill ${errors ? 'pill-bad' : warnings ? 'pill-warn' : 'pill-ok'}`}>
          {errors
            ? `${String(errors)} problem${errors === 1 ? '' : 's'}`
            : warnings
              ? `no errors · ${String(warnings)} warning${warnings === 1 ? '' : 's'}`
              : 'no problems'}
        </span>
        <span className="muted small">
          Checked as you type. “Check and plan” asks the hub, which has the last word.
        </span>
        <button
          className="btn btn-small btn-ghost wb-guide-toggle"
          type="button"
          aria-expanded={guideOpen}
          aria-controls={guideId}
          onClick={() => {
            setGuideOpen(!guideOpen);
          }}
        >
          Guide
        </button>
      </div>
      <div className="wb-grid">
        <section className="wb-outline" aria-label="Steps">
          <div className="wb-head">
            <h3>Steps</h3>
            <button
              className="btn btn-small"
              type="button"
              aria-expanded={adding}
              disabled={!a.parsed}
              onClick={() => {
                setAdding(!adding);
              }}
            >
              <span aria-hidden="true">＋</span> Add step
            </button>
          </div>
          {adding ? (
            <div className="wb-palette">
              {groups.map((g) => (
                <div key={g} className="wb-group">
                  <span className="wb-label">{g}</span>
                  {snippets
                    .filter((s) => s.group === g)
                    .map((s) => (
                      <button
                        key={s.key}
                        type="button"
                        className="wb-add"
                        onClick={() => {
                          add(s);
                        }}
                      >
                        <span className="wb-add-name">{s.label}</span>
                        <span className="muted small">{s.hint}</span>
                      </button>
                    ))}
                </div>
              ))}
              <p className="muted small">
                Added after the step the caret is in, or at the end. Capitals such as DEVICE are yours to fill in.
              </p>
            </div>
          ) : null}
          {a.parsed ? (
            <ol className="wb-rows">
              {a.steps.map((s, i) => {
                const mine = a.problems.filter((p) => p.step === i);
                const bad = mine.filter((p) => p.severity === 'error').length;
                return (
                  <li key={`${String(i)}-${s.id}`}>
                    <button
                      type="button"
                      className="wb-row"
                      aria-current={i === selected ? 'step' : undefined}
                      onClick={() => {
                        goTo(s.line);
                      }}
                    >
                      <span className="wb-no">{i + 1}</span>
                      <span className="wb-row-main">
                        <span className="wb-row-head">
                          <span className="name">{s.id || 'unnamed'}</span>
                          <span className={`wb-kind wb-${s.tone}`}>{toneWord[s.tone]}</span>
                        </span>
                        <span className="wb-sum">{s.summary}</span>
                      </span>
                      {bad > 0 ? (
                        <span
                          className="wb-mark wb-mark-bad"
                          aria-label={`${String(bad)} problem${bad === 1 ? '' : 's'}`}
                        >
                          {bad}
                        </span>
                      ) : mine.length > 0 ? (
                        <span
                          className="wb-mark wb-mark-warn"
                          aria-label={`${String(mine.length)} warning${mine.length === 1 ? '' : 's'}`}
                        >
                          {mine.length}
                        </span>
                      ) : s.dangerous ? (
                        <span className="wb-mark wb-mark-warn">needs grant</span>
                      ) : null}
                    </button>
                  </li>
                );
              })}
            </ol>
          ) : (
            <p className="muted small">
              The file does not parse yet, so its steps cannot be listed. See the problems below it.
            </p>
          )}
          {a.parsed && a.steps.length === 0 ? <p className="muted small">No steps yet. Add the first one.</p> : null}
        </section>

        <section className="wb-main" aria-label="Runbook file">
          <div className="code" ref={scroller}>
            <div className="code-inner">
              <div className="code-lines" aria-hidden="true">
                {lines.map((l, i) => {
                  const n = i + 1;
                  const sev = worst.get(n);
                  const inStep = step !== undefined && n >= step.line && n <= step.endLine;
                  return (
                    <div
                      key={n}
                      className={`code-line${n === line ? ' is-cur' : ''}${inStep ? ' is-sel' : ''}${sev === 'error' ? ' is-err' : sev === 'warning' ? ' is-warn' : ''}`}
                    >
                      <span className="code-no">{n}</span>
                      <span className="code-text">
                        {l.indent}
                        <span className="y-punct">{l.dash}</span>
                        <span className="y-key">{l.key}</span>
                        <span className="y-punct">{l.sep}</span>
                        {l.parts.map((p, k) => (
                          <span key={k} className={p.cls}>
                            {p.text}
                          </span>
                        ))}
                        <span className="y-com">{l.comment}</span>
                      </span>
                    </div>
                  );
                })}
              </div>
              <textarea
                ref={area}
                className="code-input"
                aria-label="Runbook file, YAML"
                aria-invalid={invalid || errors > 0}
                wrap="off"
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                autoComplete="off"
                value={value}
                onChange={(e) => {
                  onChange(e.target.value);
                  setLine(e.target.value.slice(0, e.target.selectionStart).split('\n').length);
                }}
                onKeyDown={onKeyDown}
                onKeyUp={readCaret}
                onClick={readCaret}
              />
            </div>
          </div>
          <p className="code-help" aria-live="polite">
            {help ? (
              <>
                <span className="y-key">{help.key}</span>
                <span>{help.text}</span>
              </>
            ) : (
              <span className="muted">
                Put the caret on a line to see what it means. Tab indents; Enter keeps the indent.
              </span>
            )}
          </p>
          {a.problems.length > 0 ? (
            <ul className="wb-problems" aria-label="Problems">
              {a.problems.map((p) => (
                <li key={`${String(p.line)}${p.message}`}>
                  <button
                    type="button"
                    className="wb-prob"
                    onClick={() => {
                      goTo(p.line);
                    }}
                  >
                    <span className={`pill ${p.severity === 'error' ? 'pill-bad' : 'pill-warn'}`}>{p.severity}</span>
                    <span className="wb-prob-line">line {p.line}</span>
                    <span className="wb-prob-msg">{p.message}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
        </section>

        {guideOpen ? (
          <aside id={guideId} className="wb-guide" aria-label="Guide">
            <div className="wb-head">
              <h3>Guide</h3>
              <button
                className="btn btn-ghost btn-small"
                type="button"
                aria-label="Close the guide"
                onClick={() => {
                  setGuideOpen(false);
                }}
              >
                ✕
              </button>
            </div>
            <div className="wb-card">
              <div className="wb-head">
                <h4>{entry.title}</h4>
                {entry.policy ? (
                  <span className={`pill ${entry.policy === 'dangerous' ? 'pill-bad' : 'pill-ok'}`}>
                    policy: {entry.policy}
                  </span>
                ) : null}
              </div>
              <p>{entry.lead}</p>
              {entry.fields.map(([k, v]) => (
                <div key={k} className="wb-kv">
                  <span className="y-key">{k}</span>
                  <span>{v}</span>
                </div>
              ))}
              {entry.notes.map((n) => (
                <p key={n} className="muted small">
                  {n}
                </p>
              ))}
            </div>
            <h3>The four kinds of step</h3>
            <div className="wb-kv">
              <span className="wb-kind wb-act">action</span>
              <span>Does something: a restart, a command, a webhook. It can name a rollback that undoes it.</span>
            </div>
            <div className="wb-kv">
              <span className="wb-kind wb-check">check</span>
              <span>Waits until something is true, and fails if it never is.</span>
            </div>
            <div className="wb-kv">
              <span className="wb-kind wb-ask">prompt</span>
              <span>Stops and asks a person.</span>
            </div>
            <div className="wb-kv">
              <span className="wb-kind wb-wait">wait</span>
              <span>Pauses for a set time.</span>
            </div>
            <h3>Writing values</h3>
            <div className="wb-kv">
              <span className="y-var">{'${{ vars.name }}'}</span>
              <span>A var from this file. Filled in when the file loads.</span>
            </div>
            <div className="wb-kv">
              <span className="y-var">{'{{ .Input.step-id }}'}</span>
              <span>A prompt answer. Only in a webhook body or headers, and in log and notify text.</span>
            </div>
            <div className="wb-kv">
              <span className="y-num">30s 5m 1h</span>
              <span>Times. Add them up as 1h30m.</span>
            </div>
            <p className="muted small">
              The whole reference is in{' '}
              <a href="https://github.com/gvart/hearth/blob/main/docs/runbooks.md">docs/runbooks.md</a>.
            </p>
          </aside>
        ) : null}
      </div>
    </div>
  );
}
