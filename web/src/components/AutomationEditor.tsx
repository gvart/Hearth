import { useEffect, useId, useMemo, useRef, useState } from 'react';
import type { AutomationDryRun, AutomationProblem, PolicyDecision } from '../api/automations.ts';
import { useAutomation, useDryRunAutomation, useSaveAutomation } from '../api/automations.ts';
import { useDevices } from '../api/hooks.ts';
import { ApiError } from '../api/client.ts';
import type {
  AutomationModel,
  Block,
  FieldSpec,
  FieldValue,
  ReadOnlyYaml,
  Section,
  StepBlock,
  StepRef,
} from '../automations/model.ts';
import {
  addStep,
  moveStep,
  newAutomationYaml,
  readAutomation,
  removeStep,
  setField,
  setKey,
  setLocal,
  stepSpecs,
} from '../automations/model.ts';
import { mayEdit, savedNotice } from '../automations/session.ts';
import { AutomationRuns, DeleteAutomationButton } from './AutomationRuns.tsx';
import { Modal } from './Modal.tsx';

const listRoute = '#/automations';

/** Opens an automation of the hub, or a new one without an id. */
export function AutomationEditor({ id }: { id?: string }) {
  if (id === undefined) {
    return <Editor initial={newAutomationYaml('my-automation')} revision="" />;
  }
  return <ExistingAutomation id={id} />;
}

function ExistingAutomation({ id }: { id: string }) {
  const automation = useAutomation(id);
  if (automation.isPending) {
    return (
      <main className="content">
        <p className="muted">Loading {id}…</p>
      </main>
    );
  }
  if (automation.isError) {
    return (
      <main className="content">
        <div className="error-box" role="alert">
          Could not load {id}: {automation.error.message}
          <a href={listRoute}>Back to automations</a>
        </div>
      </main>
    );
  }
  return (
    <Editor
      id={id}
      file={automation.data.file}
      initial={automation.data.yaml}
      revision={automation.data.revision}
      problems={automation.data.problems}
    />
  );
}

interface EditorProps {
  id?: string;
  file?: string;
  initial: string;
  revision: string;
  problems?: AutomationProblem[];
}

function Editor({ id, file, initial, revision: initialRevision, problems = [] }: EditorProps) {
  const [source, setSource] = useState(initial);
  const [saved, setSaved] = useState(initial);
  const [revision, setRevision] = useState(initialRevision);
  const [view, setView] = useState<'visual' | 'yaml'>('visual');
  const [editError, setEditError] = useState('');
  const [savedNote, setSavedNote] = useState('');
  const [loadProblems, setLoadProblems] = useState(problems);
  const [dryRunResult, setDryRunResult] = useState<AutomationDryRun | null>(null);
  const [leaving, setLeaving] = useState(false);
  const save = useSaveAutomation();
  const dryRun = useDryRunAutomation();
  const read = useMemo(() => readAutomation(source), [source]);
  const dirty = source !== saved;
  const editErrorBox = useRef<HTMLDivElement>(null);

  // The field that was refused may be far below this message.
  useEffect(() => {
    if (editError) {
      editErrorBox.current?.scrollIntoView({ block: 'center' });
    }
  }, [editError]);

  useEffect(() => {
    if (!dirty) {
      return undefined;
    }
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener('beforeunload', warn);
    return () => {
      window.removeEventListener('beforeunload', warn);
    };
  }, [dirty]);

  /** Every change of the file goes here: what was checked no longer holds. */
  const change = (next: string) => {
    // A save in flight is of the file as it was sent.
    if (!mayEdit(save.isPending)) {
      return;
    }
    setSource(next);
    setDryRunResult(null);
    setSavedNote('');
    setEditError('');
    save.reset();
    dryRun.reset();
  };

  const edit = (fn: (current: string) => string) => {
    try {
      change(fn(source));
    } catch (err) {
      setEditError(err instanceof Error ? err.message : String(err));
    }
  };

  const body = { id, yaml: source, revision };
  const runDryRun = () => {
    setSavedNote('');
    dryRun.mutate(body, { onSuccess: setDryRunResult });
  };
  const runSave = () => {
    // Save stays enabled while the file is clean: a field being typed in
    // writes to the file only as this click takes the focus from it.
    if (!dirty && id !== undefined) {
      setSavedNote('No changes to save.');
      return;
    }
    setSavedNote('');
    save.mutate(body, {
      onSuccess: (res) => {
        setSaved(source);
        setLoadProblems([]);
        setRevision(res.revision);
        setDryRunResult(null);
        setSavedNote(savedNotice(res));
        if (id === undefined) {
          window.location.hash = `#/automations/edit/${encodeURIComponent(res.id)}`;
        }
      },
      onError: (err) => {
        // The dry run lists each problem with its line.
        if (err instanceof ApiError && err.code === 'invalid') {
          runDryRun();
        }
      },
    });
  };

  const busy = save.isPending || dryRun.isPending;
  const yamlOnly = !read.ok && read.yamlOnly === true ? read.problems[0]?.message : undefined;
  const shownView = yamlOnly === undefined ? view : 'yaml';

  return (
    <main className="content auto-editor">
      <div className="page-head auto-head">
        <div className="auto-title">
          <a
            className="muted small"
            href={listRoute}
            onClick={(e) => {
              if (dirty) {
                e.preventDefault();
                setLeaving(true);
              }
            }}
          >
            Automations
          </a>
          <h1 className="mono">{id ?? 'New automation'}</h1>
          <p className="muted small" aria-live="polite">
            {file ?? 'Not saved yet'}
            {dirty ? ' · unsaved changes' : ''}
          </p>
        </div>
        <div className="auto-actions">
          <div className="auto-view" role="group" aria-label="Editor view">
            {(['visual', 'yaml'] as const).map((v) => (
              <button
                key={v}
                type="button"
                className="btn btn-small"
                aria-pressed={shownView === v}
                disabled={v === 'visual' && yamlOnly !== undefined}
                onClick={() => {
                  setView(v);
                }}
              >
                {v === 'visual' ? 'Visual' : 'YAML'}
              </button>
            ))}
          </div>
          {id !== undefined ? <DeleteAutomationButton id={id} disabled={busy} /> : null}
          <button type="button" className="btn" disabled={busy} onClick={runDryRun}>
            {dryRun.isPending ? 'Checking…' : 'Dry run'}
          </button>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={runSave}>
            {save.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      {loadProblems.length > 0 && !dirty ? (
        <Problems title="The hub cannot load this file" problems={loadProblems} />
      ) : null}
      {yamlOnly !== undefined ? (
        <div className="error-box" role="alert">
          <strong>This file opens in the YAML view only</strong>
          {yamlOnly}
        </div>
      ) : null}
      {editError ? (
        <div ref={editErrorBox} className="error-box" role="alert">
          That edit was not applied: {editError}
        </div>
      ) : null}
      {save.isPending ? (
        <p className="notice" role="status">
          Saving. If policy holds this for approval, it finishes once someone approves it on the Approvals page.
        </p>
      ) : null}
      {save.isError ? (
        <div className="error-box" role="alert">
          Not saved: {save.error.message}
        </div>
      ) : null}
      {dryRun.isError ? (
        <div className="error-box" role="alert">
          The dry run failed: {dryRun.error.message}
        </div>
      ) : null}
      {savedNote ? (
        <p className="notice" role="status">
          {savedNote}
        </p>
      ) : null}
      {dryRunResult ? <DryRunResult result={dryRunResult} /> : null}

      <fieldset className="auto-lock" disabled={!mayEdit(save.isPending)}>
        {shownView === 'yaml' ? (
          <YamlView source={source} problems={read.ok || read.yamlOnly ? [] : read.problems} onChange={change} />
        ) : read.ok ? (
          <VisualView model={read.model} isNew={id === undefined} edit={edit} />
        ) : (
          <>
            <Problems title="This YAML cannot be shown visually" problems={read.problems} />
            <button
              type="button"
              className="btn"
              onClick={() => {
                setView('yaml');
              }}
            >
              Fix it in YAML
            </button>
          </>
        )}
      </fieldset>
      {id !== undefined ? <AutomationRuns id={id} /> : null}
      {leaving ? (
        <Modal
          className="dialog"
          labelledBy="leave-title"
          onClose={() => {
            setLeaving(false);
          }}
        >
          <h2 id="leave-title">Leave without saving?</h2>
          <p>Your changes to {id ?? 'the new automation'} are not saved and will be lost.</p>
          <div className="form-actions">
            <button
              className="btn btn-ghost"
              type="button"
              onClick={() => {
                setLeaving(false);
              }}
            >
              Keep editing
            </button>
            <a className="btn btn-danger" href={listRoute}>
              Leave
            </a>
          </div>
        </Modal>
      ) : null}
    </main>
  );
}

function Problems({ title, problems }: { title: string; problems: AutomationProblem[] }) {
  return (
    <div className="error-box" role="alert">
      <strong>{title}</strong>
      <ul className="auto-problems">
        {problems.map((p) => (
          <li key={`${String(p.line)}:${p.message}`}>
            {p.line > 0 ? `Line ${String(p.line)}: ` : ''}
            {p.message}
          </li>
        ))}
      </ul>
    </div>
  );
}

function YamlView({
  source,
  problems,
  onChange,
}: {
  source: string;
  problems: AutomationProblem[];
  onChange: (next: string) => void;
}) {
  return (
    <>
      {problems.length > 0 ? <Problems title="This YAML does not parse" problems={problems} /> : null}
      <label className="field">
        Automation file
        <textarea
          className="auto-yaml"
          value={source}
          rows={Math.min(32, Math.max(14, source.split('\n').length + 1))}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          wrap="off"
          onChange={(e) => {
            onChange(e.target.value);
          }}
        />
      </label>
    </>
  );
}

type Edit = (fn: (current: string) => string) => void;

const sectionInfo: Record<Section, { title: string; hint: string; noun: string }> = {
  triggers: { title: 'Triggers', hint: 'Any of these starts a run.', noun: 'trigger' },
  conditions: { title: 'Conditions', hint: 'All must hold, or the run is skipped.', noun: 'condition' },
  actions: { title: 'Actions', hint: 'Run in order. The first failure or denial ends the run.', noun: 'action' },
};

function VisualView({ model, isNew, edit }: { model: AutomationModel; isNew: boolean; edit: Edit }) {
  return (
    <div className="auto-visual">
      <section className="auto-card" aria-labelledby="auto-general">
        <h2 id="auto-general">General</h2>
        <div className="auto-fields">
          {isNew ? (
            <TextField
              label="Id"
              value={model.id}
              required
              help="Lowercase letters, digits, - and _."
              onCommit={(v) => {
                edit((s) => setKey(s, null, 'id', v));
              }}
            />
          ) : null}
          <TextField
            label="Description"
            value={model.description}
            onCommit={(v) => {
              edit((s) => setKey(s, null, 'description', v));
            }}
          />
          <SelectField
            label="While a run is in progress"
            value={model.mode}
            options={['single', 'queued', 'restart']}
            emptyLabel="Default (single)"
            onChange={(v) => {
              edit((s) => setKey(s, null, 'mode', v));
            }}
          />
        </div>
        <label className="auto-check">
          <input
            type="checkbox"
            checked={model.local}
            onChange={(e) => {
              edit((s) => setLocal(s, e.target.checked));
            }}
          />
          Run on the device (works when the hub is down)
        </label>
        {model.local ? <LocalNote model={model} /> : null}
        {model.extras.map((e) => (
          <ReadOnly key={e.yaml} part={e} />
        ))}
      </section>
      {(['triggers', 'conditions', 'actions'] as const).map((section) => (
        <SectionView key={section} section={section} model={model} edit={edit} />
      ))}
    </div>
  );
}

/** The first protocol minor version whose agents run local automations. */
const localRulesMinor = 12;

/** What running on the device means, and whether the device's agent can. */
function LocalNote({ model }: { model: AutomationModel }) {
  const devices = useDevices();
  const first = model.blocks.triggers[0];
  const from = first?.kind === 'step' && typeof first.values.from === 'string' ? first.values.from : '';
  const device = from
    ? devices.data?.find((d) => d.id === from || d.name === from || d.hostname.toLowerCase() === from.toLowerCase())
    : undefined;
  const minor = device?.facts.protocol_minor ?? 0;
  return (
    <div className="auto-local small">
      <p className="muted">
        The device in the checks&apos; <strong>From device</strong> runs it itself and reports its runs when it
        reaches a hub again; the hub stops watching it. Only HTTP, TCP and DNS checks from that device can trigger
        it, and it can only restart a service on that device or run a check from it.
      </p>
      {!from ? <p className="error">Set From device on its checks.</p> : null}
      {device && minor < localRulesMinor ? (
        <p className="error" role="alert">
          The agent of {device.name} is too old to run automations itself: upgrade it. Until then the automation
          does not run.
        </p>
      ) : null}
    </div>
  );
}

function SectionView({ section, model, edit }: { section: Section; model: AutomationModel; edit: Edit }) {
  const info = sectionInfo[section];
  const types = Object.keys(stepSpecs[section]);
  const [type, setType] = useState(types[0] ?? '');
  const focus = useRef<string | null>(null);
  const blocks = model.blocks[section];
  const raw = model.rawSections[section];
  const addId = `auto-add-${section}`;

  // Keeps the keyboard on the step that moved, or on Add after a removal.
  useEffect(() => {
    if (focus.current !== null) {
      document.getElementById(focus.current)?.focus();
      focus.current = null;
    }
  });

  return (
    <section className="auto-card" aria-labelledby={`auto-${section}`}>
      <h2 id={`auto-${section}`}>{info.title}</h2>
      <p className="muted small">{info.hint}</p>
      {raw ? <ReadOnly part={raw} /> : null}
      {blocks.length > 0 ? (
        <ol className="auto-steps">
          {blocks.map((block) => (
            <li key={block.index}>
              <StepView
                block={block}
                section={section}
                count={blocks.length}
                edit={edit}
                onFocus={(target) => {
                  focus.current = target;
                }}
                addId={addId}
              />
            </li>
          ))}
        </ol>
      ) : null}
      {raw ? null : types.length > 0 ? (
        <div className="auto-add">
          <label className="field">
            New {info.noun}
            <select
              value={type}
              onChange={(e) => {
                setType(e.target.value);
              }}
            >
              {types.map((t) => (
                <option key={t} value={t}>
                  {stepSpecs[section][t]?.label ?? t}
                </option>
              ))}
            </select>
          </label>
          <button
            id={addId}
            type="button"
            className="btn"
            onClick={() => {
              edit((s) => addStep(s, section, type));
            }}
          >
            Add {info.noun}
          </button>
        </div>
      ) : (
        <p className="muted small">The hub has no condition types yet.</p>
      )}
    </section>
  );
}

function StepView({
  block,
  section,
  count,
  edit,
  onFocus,
  addId,
}: {
  block: Block;
  section: Section;
  count: number;
  edit: Edit;
  onFocus: (id: string) => void;
  addId: string;
}) {
  const { index } = block;
  const position = `${sectionInfo[section].noun} ${String(index + 1)}`;
  const title = block.kind === 'step' ? block.spec.label : 'Read-only step';
  const buttonId = (dir: string, i: number) => `auto-${section}-${String(i)}-${dir}`;
  const move = (delta: -1 | 1, dir: string) => {
    edit((s) => moveStep(s, section, index, delta));
    const next = index + delta;
    // At the end of the list the button is disabled: use the other one.
    const edge = next === 0 || next === count - 1;
    onFocus(buttonId(edge ? (dir === 'up' ? 'down' : 'up') : dir, next));
  };

  return (
    <article className="auto-step" aria-label={`${title}, ${position}`}>
      <header className="auto-step-head">
        <div className="auto-step-title">
          <strong>{title}</strong>
          {block.kind === 'step' ? <span className="mono muted">{block.type}</span> : null}
        </div>
        <div className="auto-step-buttons">
          <button
            id={buttonId('up', index)}
            type="button"
            className="btn btn-small btn-ghost"
            disabled={index === 0}
            aria-label={`Move ${position} up`}
            onClick={() => {
              move(-1, 'up');
            }}
          >
            Up
          </button>
          <button
            id={buttonId('down', index)}
            type="button"
            className="btn btn-small btn-ghost"
            disabled={index === count - 1}
            aria-label={`Move ${position} down`}
            onClick={() => {
              move(1, 'down');
            }}
          >
            Down
          </button>
          <button
            type="button"
            className="btn btn-small btn-ghost"
            aria-label={`Remove ${position}`}
            onClick={() => {
              edit((s) => removeStep(s, section, index));
              onFocus(addId);
            }}
          >
            Remove
          </button>
        </div>
      </header>
      {block.kind === 'raw' ? <ReadOnly part={block} /> : <StepFields block={block} section={section} edit={edit} />}
    </article>
  );
}

function StepFields({ block, section, edit }: { block: StepBlock; section: Section; edit: Edit }) {
  const ref: StepRef = { section, index: block.index };
  return (
    <>
      <div className="auto-fields">
        {block.spec.fields.map((field) => (
          <FieldInput
            key={field.key}
            field={field}
            value={block.values[field.key]}
            shadowed={block.extras.some((e) => e.yaml.startsWith(`${field.key}:`))}
            onChange={(v) => {
              edit((s) => setField(s, ref, field, v));
            }}
          />
        ))}
        <TextField
          label="Step id"
          value={block.id}
          help="Optional."
          onCommit={(v) => {
            edit((s) => setKey(s, ref, 'id', v));
          }}
        />
        <TextField
          label="Note"
          value={block.description}
          help="Optional."
          onCommit={(v) => {
            edit((s) => setKey(s, ref, 'description', v));
          }}
        />
      </div>
      {block.extras.map((e) => (
        <ReadOnly key={e.yaml} part={e} />
      ))}
    </>
  );
}

function FieldInput({
  field,
  value,
  shadowed,
  onChange,
}: {
  field: FieldSpec;
  value: FieldValue | undefined;
  shadowed: boolean;
  onChange: (value: FieldValue | undefined) => void;
}) {
  // Its value is shown read-only below: an input here would replace it.
  if (shadowed) {
    return null;
  }
  const { label, required, help } = field;
  switch (field.kind) {
    case 'bool':
      return (
        <label className="auto-check">
          <input
            type="checkbox"
            checked={value === true}
            onChange={(e) => {
              onChange(e.target.checked ? true : undefined);
            }}
          />
          {label}
        </label>
      );
    case 'select':
      return (
        <SelectField
          label={label}
          value={typeof value === 'string' ? value : ''}
          options={field.options ?? []}
          emptyLabel={required ? 'Choose…' : 'Not set'}
          required={required}
          help={help}
          onChange={onChange}
        />
      );
    case 'list':
      return (
        <LinesField
          label={label}
          required={required}
          help={help}
          text={Array.isArray(value) ? (value as string[]).join('\n') : ''}
          parse={(text) => ({ value: text.split('\n').map((l) => l.trim()).filter((l) => l !== '') })}
          onCommit={onChange}
        />
      );
    case 'map':
      return (
        <LinesField
          label={label}
          required={required}
          help={help}
          text={Array.isArray(value) ? (value as [string, string][]).map(([k, v]) => `${k}: ${v}`).join('\n') : ''}
          parse={parseEntries}
          onCommit={onChange}
        />
      );
    default:
      return (
        <TextField
          label={label}
          value={typeof value === 'string' ? value : ''}
          required={required}
          help={help}
          multiline={field.kind === 'multiline'}
          inputMode={field.kind === 'number' ? 'decimal' : undefined}
          placeholder={field.kind === 'duration' ? 'e.g. 30s, 5m' : undefined}
          onCommit={onChange}
        />
      );
  }
}

function parseEntries(text: string): { value?: [string, string][]; error?: string } {
  const entries: [string, string][] = [];
  for (const line of text.split('\n')) {
    if (line.trim() === '') {
      continue;
    }
    const at = line.indexOf(':');
    if (at <= 0) {
      return { error: `"${line.trim()}" needs the form Name: value.` };
    }
    entries.push([line.slice(0, at).trim(), line.slice(at + 1).trim()]);
  }
  return { value: entries };
}

/** Help, and a required field's reminder, tied to their input. */
function Hint({ id, help, missing }: { id: string; help?: string; missing: boolean }) {
  if (!help && !missing) {
    return null;
  }
  return (
    <span id={id} className={missing ? 'error auto-hint' : 'muted auto-hint'}>
      {missing ? 'Required. ' : ''}
      {help}
    </span>
  );
}

/**
 * A text input that writes to the file when it loses focus: a value cleared
 * on the way to a new one must not remove the key and its comment.
 */
function TextField({
  label,
  value,
  required = false,
  help,
  multiline = false,
  inputMode,
  placeholder,
  onCommit,
}: {
  label: string;
  value: string;
  required?: boolean;
  help?: string;
  multiline?: boolean;
  inputMode?: 'decimal';
  placeholder?: string;
  onCommit: (value: string) => void;
}) {
  const [draft, setDraft] = useState(value);
  const [shown, setShown] = useState(value);
  const hintId = useId();
  if (shown !== value) {
    setShown(value);
    setDraft(value);
  }
  const missing = required && draft.trim() === '';
  const props = {
    value: draft,
    required,
    placeholder,
    'aria-invalid': missing,
    'aria-describedby': help || missing ? hintId : undefined,
    onChange: (e: { target: { value: string } }) => {
      setDraft(e.target.value);
    },
    onBlur: () => {
      if (draft !== value) {
        onCommit(draft);
      }
    },
  };
  return (
    <label className={multiline ? 'field auto-wide' : 'field'}>
      {label}
      {multiline ? <textarea rows={3} {...props} /> : <input type="text" inputMode={inputMode} {...props} />}
      <Hint id={hintId} help={help} missing={missing} />
    </label>
  );
}

function SelectField({
  label,
  value,
  options,
  emptyLabel,
  required = false,
  help,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  emptyLabel: string;
  required?: boolean;
  help?: string;
  onChange: (value: string) => void;
}) {
  const hintId = useId();
  const missing = required && value === '';
  // A value the hub may reject is still the file's value: keep it selectable.
  const all = value === '' || options.includes(value) ? options : [value, ...options];
  return (
    <label className="field">
      {label}
      <select
        value={value}
        required={required}
        aria-invalid={missing}
        aria-describedby={help || missing ? hintId : undefined}
        onChange={(e) => {
          onChange(e.target.value);
        }}
      >
        <option value="">{emptyLabel}</option>
        {all.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
      <Hint id={hintId} help={help} missing={missing} />
    </label>
  );
}

/** A list or map, edited as lines and written when it loses focus. */
function LinesField({
  label,
  required = false,
  help,
  text,
  parse,
  onCommit,
}: {
  label: string;
  required?: boolean;
  help?: string;
  text: string;
  parse: (text: string) => { value?: FieldValue; error?: string };
  onCommit: (value: FieldValue | undefined) => void;
}) {
  const [draft, setDraft] = useState(text);
  const [shown, setShown] = useState(text);
  const [error, setError] = useState('');
  const hintId = useId();
  if (shown !== text) {
    setShown(text);
    setDraft(text);
    setError('');
  }
  const missing = required && draft.trim() === '';
  return (
    <label className="field auto-wide">
      {label}
      <textarea
        className="mono"
        rows={Math.max(2, draft.split('\n').length)}
        value={draft}
        spellCheck={false}
        required={required}
        aria-invalid={missing || error !== ''}
        aria-describedby={hintId}
        onChange={(e) => {
          setDraft(e.target.value);
        }}
        onBlur={() => {
          if (draft === text) {
            setError('');
            return;
          }
          const parsed = parse(draft);
          setError(parsed.error ?? '');
          if (parsed.error === undefined) {
            onCommit(parsed.value);
          }
        }}
      />
      {error ? (
        <span id={hintId} className="error auto-hint" role="alert">
          {error}
        </span>
      ) : (
        <Hint id={hintId} help={help} missing={missing} />
      )}
    </label>
  );
}

/** Part of the file the form cannot edit, exactly as it is written. */
function ReadOnly({ part }: { part: ReadOnlyYaml }) {
  return (
    <figure className="auto-raw">
      <figcaption className="small">
        <strong>Read-only YAML.</strong> {part.reason} It is kept as written; change it in the YAML view.
      </figcaption>
      {/* Focusable so that the keyboard can scroll a wide block. */}
      <pre tabIndex={0} aria-label="Read-only YAML">
        <code>{part.yaml}</code>
      </pre>
    </figure>
  );
}

const decisionLabel: Record<PolicyDecision, string> = {
  allow: 'Allowed',
  confirm: 'Needs approval',
  deny: 'Denied',
};

function Decision({ decision }: { decision: PolicyDecision }) {
  return <span className={`badge auto-decision auto-decision-${decision}`}>{decisionLabel[decision]}</span>;
}

function DryRunResult({ result }: { result: AutomationDryRun }) {
  return (
    <section className="auto-card auto-result" aria-labelledby="auto-dry-run" role="status">
      <h2 id="auto-dry-run">Dry run</h2>
      <p className="muted small">Checked by the hub. Nothing was saved and nothing ran.</p>
      {result.problems.length > 0 ? <Problems title="The hub would refuse this file" problems={result.problems} /> : null}
      {result.blocked ? (
        <div className="error-box">
          <strong>It could not be saved right now</strong>
          {result.blocked}
        </div>
      ) : null}
      {result.save ? (
        <ul className="auto-decisions">
          <li>
            <div>
              <strong>Save this file</strong>
              <span className="mono muted small">
                {result.save.action} · {result.save.class}
              </span>
              {result.save.reason ? <span className="small">{result.save.reason}</span> : null}
            </div>
            <Decision decision={result.save.decision} />
          </li>
          {result.actions.map((a) => (
            <li key={a.step}>
              <div>
                <strong className="mono">{a.step}</strong>
                <span className="mono muted small">
                  {a.action} · {a.class}
                  {a.target ? ` · ${a.target}` : ''}
                </span>
                {a.reason ? <span className="small">{a.reason}</span> : null}
              </div>
              <Decision decision={a.decision} />
            </li>
          ))}
        </ul>
      ) : null}
      {result.plan ? (
        <details>
          <summary>What it would do</summary>
          <pre tabIndex={0} aria-label="Plan" className="auto-plan">
            {result.plan}
          </pre>
        </details>
      ) : null}
    </section>
  );
}
