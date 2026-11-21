import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { useDevices } from '../api/hooks.ts';
import {
  analyze,
  docOf,
  guide,
  highlight,
  insertStep,
  keyHelp,
  snippets,
  stepAt,
  type DeviceCeiling,
  type Snippet,
  type StepInfo,
  type StepTone,
} from '../runbookdoc.ts';
import { fieldsOf, moveStep, removeStep, setField, type StepField } from '../runbookfields.ts';
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
 * for the key under the caret, steps to add, the step the caret is in as a
 * form, and a guide on demand. The form and the file are one text: a field
 * changes its value in the file and nothing else, and typing in the file
 * shows in the form.
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
  const [formOpen, setFormOpen] = useState(true);
  // Full screen hides the app around the editor (RunbookWorkbench.css does it from this class).
  const [full, setFull] = useState(false);
  useEffect(() => {
    if (!full) {
      return;
    }
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape' && !e.defaultPrevented) {
        setFull(false);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
    };
  }, [full]);
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

  /** Takes a change the form made: the file, and the step to stay on (its first line does not move under it). */
  const fromForm = (text: string | undefined, stay: number): boolean => {
    if (text === undefined) {
      return false;
    }
    if (text !== value) {
      setLine(analyze(text, ceilings).steps[stay]?.line ?? 0);
      onChange(text);
    }
    return true;
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
    <div className={full ? 'wb wb-full' : 'wb'}>
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
        <span className="wb-tools">
          <button
            className="btn btn-small btn-ghost"
            type="button"
            aria-pressed={formOpen}
            onClick={() => {
              setFormOpen(!formOpen);
            }}
          >
            Form
          </button>
          <button
            className="btn btn-small btn-ghost"
            type="button"
            aria-expanded={guideOpen}
            aria-controls={guideId}
            onClick={() => {
              setGuideOpen(!guideOpen);
            }}
          >
            Guide
          </button>
          <button
            className="btn btn-small btn-ghost"
            type="button"
            aria-pressed={full}
            onClick={() => {
              setFull(!full);
            }}
          >
            {full ? 'Exit full screen' : 'Full screen'}
          </button>
        </span>
      </div>
      <div className={formOpen ? 'wb-grid wb-with-form' : 'wb-grid'}>
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

        {formOpen ? (
          <section className="wb-form" aria-label="The step as a form">
            {step ? (
              <StepForm
                // One form per step: a field keeps the focus while its own step is edited.
                key={selected}
                step={step}
                no={selected + 1}
                fields={fieldsOf(value, selected)}
                devices={ceilings.flatMap((c) => c.names.slice(0, 1))}
                onField={(path, text) => fromForm(setField(value, selected, path, text), selected)}
                move={(by) => {
                  fromForm(moveStep(value, a.steps, selected, by), selected + by);
                }}
                canMove={(by) => moveStep(value, a.steps, selected, by) !== undefined}
                remove={() => {
                  fromForm(removeStep(value, a.steps, selected), Math.min(selected, a.steps.length - 2));
                }}
                canRemove={removeStep(value, a.steps, selected) !== undefined}
              />
            ) : (
              <>
                <h3>Step</h3>
                <p className="muted small">
                  {a.parsed
                    ? 'Pick a step on the left, or put the caret in one, to edit it as a form. The file changes with every field, and nothing else in it moves.'
                    : 'The file does not parse yet. Fix it in the file first.'}
                </p>
              </>
            )}
          </section>
        ) : null}

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

/**
 * One step as a form: every value of it a field, in the file's order, under
 * the key that holds it. A field writes its value into the file as it is
 * typed; what cannot be written there without disturbing the rest says so.
 */
function StepForm({
  step,
  no,
  fields,
  devices,
  onField,
  move,
  canMove,
  remove,
  canRemove,
}: {
  step: StepInfo;
  no: number;
  fields: StepField[];
  devices: string[];
  onField: (path: string, text: string) => boolean;
  move: (by: -1 | 1) => void;
  canMove: (by: -1 | 1) => boolean;
  remove: () => void;
  canRemove: boolean;
}) {
  // What is being typed, as typed: the file holds the value without the space at its ends, the field keeps it.
  const [draft, setDraft] = useState<{ path: string; text: string; refused: boolean }>();
  const listId = useId();

  return (
    <>
      <div className="wb-head">
        <h3>
          Step {no} <span className={`wb-kind wb-${step.tone}`}>{toneWord[step.tone]}</span>
        </h3>
        <span className="wb-step-tools">
          <button
            className="btn btn-small btn-ghost"
            type="button"
            aria-label="Move the step up"
            disabled={!canMove(-1)}
            onClick={() => {
              move(-1);
            }}
          >
            ↑
          </button>
          <button
            className="btn btn-small btn-ghost"
            type="button"
            aria-label="Move the step down"
            disabled={!canMove(1)}
            onClick={() => {
              move(1);
            }}
          >
            ↓
          </button>
          <button className="btn btn-small btn-ghost" type="button" disabled={!canRemove} onClick={remove}>
            Remove
          </button>
        </span>
      </div>
      {fields.length === 0 ? <p className="muted small">This step has no values yet. Write them in the file.</p> : null}
      {fields.map((f, i) => {
        // A heading where the keys above the value change: "action", "action · command".
        const heading = f.group !== (fields[i - 1]?.group ?? '') ? f.group : '';
        const mine = draft?.path === f.path ? draft : undefined;
        const change = (text: string) => {
          setDraft({ path: f.path, text, refused: !onField(f.path, text) });
        };
        const blur = () => {
          setDraft(undefined);
        };
        const help = docOf(f.key);
        return (
          <div key={f.path} className="wb-field-wrap">
            {heading ? <span className="wb-label">{heading}</span> : null}
            <label className="field wb-field">
              <span className="y-key">{f.label}</span>
              {f.kind === 'block' ? (
                <textarea
                  className="wb-field-block"
                  rows={Math.min(12, Math.max(3, (mine?.text ?? f.value).split('\n').length + 1))}
                  wrap="off"
                  spellCheck={false}
                  value={mine?.text ?? f.value}
                  onChange={(e) => {
                    change(e.target.value);
                  }}
                  onBlur={blur}
                />
              ) : (
                <input
                  type="text"
                  spellCheck={false}
                  autoCapitalize="off"
                  autoComplete="off"
                  list={f.key === 'device' || f.key === 'from' ? listId : undefined}
                  value={mine?.text ?? f.value}
                  onChange={(e) => {
                    change(e.target.value);
                  }}
                  onBlur={blur}
                />
              )}
              {mine?.refused ? (
                <span className="error small" role="alert">
                  This cannot be written here without changing the lines around it. Edit it in the file.
                </span>
              ) : help ? (
                <span className="muted small">{help}</span>
              ) : null}
            </label>
          </div>
        );
      })}
      <datalist id={listId}>
        {devices.map((d) => (
          <option key={d} value={d} />
        ))}
      </datalist>
      <p className="muted small">A key that is not here yet is added in the file, with its own line.</p>
    </>
  );
}
