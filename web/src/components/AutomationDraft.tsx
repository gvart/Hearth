import { useState } from 'react';
import { draftNotice } from '../ai.ts';
import { useAIConfig, useDraftAutomation, type AutomationDraft } from '../api/ai.ts';
import { Tip } from './Tip.tsx';
import './DeviceExplain.css';

const placeholder = 'Restart pihole-FTL on the DNS Pi when DNS fails 3 times, then notify me';

/**
 * Asks the model the hub is set up with for an automation that does what
 * the operator describes. The hub validates the answer and saves nothing:
 * the draft goes into the editor, through onDraft, to review and save as
 * any edit is. Where AI is not served this shows nothing; while it is off,
 * one line saying where to turn it on.
 */
export function AutomationDraftCard({ disabled, onDraft }: { disabled: boolean; onDraft: (d: AutomationDraft) => void }) {
  const config = useAIConfig();
  const draft = useDraftAutomation();
  const [text, setText] = useState('');
  const cfg = config.data;

  if (config.isPending || cfg === null || config.isError) {
    return null;
  }
  if (!cfg?.enabled) {
    return (
      <p className="muted small">
        Describe an automation and let a model draft it: an admin turns AI on in <a href="#/settings/ai">Settings, AI</a>.
      </p>
    );
  }

  const run = (preview: boolean) => {
    draft.mutate(
      { text, preview },
      {
        onSuccess: (res) => {
          if (!res.preview) {
            onDraft(res);
          }
        },
      },
    );
  };
  const res = draft.data;
  const where = res ? `${res.provider} ${res.model} at ${res.base_url}` : '';

  return (
    <section className="panel-card" aria-labelledby="draft-title">
      <h2 className="card-label" id="draft-title">
        Write it with AI <Tip id="aidraft" />
      </h2>
      <form
        className="explain-form"
        onSubmit={(e) => {
          e.preventDefault();
          run(false);
        }}
      >
        <label className="field">
          What should it do?
          <textarea
            rows={2}
            maxLength={2000}
            placeholder={placeholder}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
            }}
          />
        </label>
        <div className="explain-actions">
          <button className="btn btn-primary" type="submit" disabled={disabled || draft.isPending || text.trim() === ''}>
            {draft.isPending ? 'Drafting…' : 'Draft it'}
          </button>
          <button
            className="btn btn-ghost"
            type="button"
            disabled={disabled || draft.isPending || text.trim() === ''}
            onClick={() => {
              run(true);
            }}
          >
            Preview what is sent
          </button>
          <span className="muted small">
            {cfg.provider === 'anthropic' ? 'Anthropic' : 'OpenAI-compatible'} · <span className="mono">{cfg.model}</span>
          </span>
        </div>
      </form>
      {draft.isError ? (
        <p className="error" role="alert">
          No draft: {draft.error.message}
        </p>
      ) : null}
      {res ? (
        <div className="explain-result" aria-live="polite">
          {res.preview ? (
            <p className="notice" role="status">
              This is what would be sent to <span className="mono">{where}</span>: {res.sent_bytes} bytes,{' '}
              {res.redactions} value{res.redactions === 1 ? '' : 's'} redacted. Nothing has been sent yet.
            </p>
          ) : (
            <p className={res.valid ? 'notice' : 'warn-box'} role="status">
              {draftNotice(res)}
            </p>
          )}
          {res.truncated.length > 0 ? <p className="muted small">Cut to fit: {res.truncated.join(', ')}.</p> : null}
          <details className="explain-sent" open={res.preview}>
            <summary>
              What was {res.preview ? 'gathered' : 'sent'}: {res.sent_bytes} bytes to {where}, {res.redactions} redacted
            </summary>
            <pre>{[res.sent.system, ...res.sent.messages.map((m) => `--- ${m.role} ---\n${m.content}`)].join('\n\n')}</pre>
          </details>
        </div>
      ) : null}
    </section>
  );
}
