import { useState } from 'react';
import { parseLogSources, previewSeenKey } from '../ai.ts';
import { useAIConfig, useExplain, type Explanation } from '../api/ai.ts';
import type { Device } from '../api/client.ts';
import { Tip } from './Tip.tsx';
import './DeviceExplain.css';

function previewSeen(): boolean {
  try {
    return localStorage.getItem(previewSeenKey) === '1';
  } catch {
    return false;
  }
}

function rememberPreview() {
  try {
    localStorage.setItem(previewSeenKey, '1');
  } catch {
    // A browser that keeps nothing shows the preview again next time.
  }
}

/**
 * Asks the model the hub is set up with what is wrong with the device. The
 * first explanation in a browser shows what would be sent before sending it;
 * every answer keeps what was sent behind "What was sent". The answer is
 * plain text, and nothing in it runs.
 */
export function DeviceExplain({ device }: { device: Device }) {
  const config = useAIConfig();
  const explain = useExplain(device.id);
  const [question, setQuestion] = useState('');
  const [logs, setLogs] = useState('');
  const parsed = parseLogSources(logs);
  const allowed = device.facts.ceiling?.logs ?? [];
  const cfg = config.data;

  const run = (preview: boolean) => {
    explain.mutate(
      { question, logs: parsed.sources, preview },
      {
        onSuccess: (res) => {
          if (res.preview) {
            rememberPreview();
          }
        },
      },
    );
  };

  return (
    <section className="panel-card card-wide" aria-labelledby="explain-title">
      <h2 className="card-label" id="explain-title">
        Explain <Tip id="ai" />
      </h2>
      {config.isPending ? (
        <p className="muted small">Loading…</p>
      ) : !cfg?.enabled ? (
        <p className="muted small">
          AI is off. An admin sets up a model (a local Ollama, or Anthropic) in <a href="#/settings/ai">Settings, AI</a>.
          Everything else works without it.
        </p>
      ) : (
        <>
          <form
            className="explain-form"
            onSubmit={(e) => {
              e.preventDefault();
              // The first time, show what would be sent; then send.
              run(!previewSeen());
            }}
          >
            <label className="field">
              Question
              <textarea
                rows={2}
                maxLength={2000}
                placeholder="Is anything wrong with it? (leave empty to ask that)"
                value={question}
                onChange={(e) => {
                  setQuestion(e.target.value);
                }}
              />
            </label>
            {allowed.length > 0 ? (
              <label className="field">
                Include the tail of a log (optional)
                <input
                  type="text"
                  className="mono"
                  placeholder={allowed[0]?.includes('*') ? 'systemd:nginx.service' : allowed[0]}
                  value={logs}
                  aria-invalid={parsed.error !== ''}
                  onChange={(e) => {
                    setLogs(e.target.value);
                  }}
                />
                <span className="muted small">
                  Up to three, comma separated. The agent allows {allowed.join(', ')}.
                </span>
              </label>
            ) : null}
            {parsed.error ? <p className="error">{parsed.error}</p> : null}
            <div className="explain-actions">
              <button className="btn btn-primary" type="submit" disabled={explain.isPending || parsed.error !== ''}>
                {explain.isPending ? 'Asking…' : 'Explain'}
              </button>
              <button
                className="btn btn-ghost"
                type="button"
                disabled={explain.isPending || parsed.error !== ''}
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
          {explain.isError ? (
            <p className="error" role="alert">
              {explain.error.message}
            </p>
          ) : null}
          {explain.data ? (
            <ExplainResult
              res={explain.data}
              pending={explain.isPending}
              onSend={() => {
                run(false);
              }}
            />
          ) : null}
        </>
      )}
    </section>
  );
}

function ExplainResult({ res, pending, onSend }: { res: Explanation; pending: boolean; onSend: () => void }) {
  const where = `${res.provider} ${res.model} at ${res.base_url}`;
  return (
    <div className="explain-result" aria-live="polite">
      {res.preview ? (
        <div className="notice" role="status">
          <p>
            This is what would be sent to <span className="mono">{where}</span>: {res.sent_bytes} bytes,{' '}
            {res.redactions} value{res.redactions === 1 ? '' : 's'} redacted. Nothing has been sent yet.
          </p>
          <div className="explain-actions">
            <button className="btn btn-primary btn-small" type="button" disabled={pending} onClick={onSend}>
              {pending ? 'Asking…' : 'Send it'}
            </button>
          </div>
        </div>
      ) : (
        <>
          <pre className="explain-answer">{res.answer}</pre>
          <p className="muted small">
            A suggestion only: nothing ran. Take any step it names through Hearth&apos;s controls, where policy decides.
          </p>
        </>
      )}
      {res.notes.map((n) => (
        <p className="muted small" key={n}>
          {n}
        </p>
      ))}
      {res.truncated.length > 0 ? (
        <p className="muted small">Cut to fit: {res.truncated.join(', ')}.</p>
      ) : null}
      <details className="explain-sent" open={res.preview}>
        <summary>
          What was {res.preview ? 'gathered' : 'sent'}: {res.sent_bytes} bytes to {where}, {res.redactions} redacted
        </summary>
        <pre>{[res.sent.system, ...res.sent.messages.map((m) => m.content)].join('\n\n')}</pre>
      </details>
    </div>
  );
}
