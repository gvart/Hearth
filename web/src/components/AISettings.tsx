import { useState } from 'react';
import { aiEditBody, aiFormReady, providers, type AIForm, type AIProvider } from '../ai.ts';
import { useAIConfig, useSaveAIConfig, type AIConfig } from '../api/ai.ts';
import { ApiError } from '../api/client.ts';
import { problemsOf } from '../api/admin.ts';
import { ProblemList } from './SettingsPage.tsx';

/** The model the hub asks, as `hearth ai set` sets it: saving asks for the password again. */
export function AISettingsCard() {
  const config = useAIConfig();
  if (config.isPending) {
    return <p className="muted small">Loading…</p>;
  }
  if (config.isError) {
    return (
      <p className="error" role="alert">
        Could not load the AI settings: {config.error.message}
      </p>
    );
  }
  if (config.data === null) {
    return (
      <section className="panel-card">
        <h2>Model</h2>
        <p className="muted small">
          This hub keeps its configuration in files. Write <code>ai.yaml</code> and load it with{' '}
          <code>hearth config import</code> on the hub host.
        </p>
      </section>
    );
  }
  return <AIForm key={config.data.revision} stored={config.data} />;
}

function formOf(c: AIConfig): AIForm {
  return {
    provider: c.provider,
    base_url: c.provider === 'openai' ? c.base_url : c.base_url === providers.anthropic.baseURL ? '' : c.base_url,
    model: c.provider === 'anthropic' && c.model === providers.anthropic.model ? '' : c.model,
    api_key: '',
    clear_api_key: false,
  };
}

function AIForm({ stored }: { stored: AIConfig }) {
  const [form, setForm] = useState<AIForm>(() => formOf(stored));
  const save = useSaveAIConfig();
  const set = (patch: Partial<AIForm>) => {
    save.reset();
    setForm({ ...form, ...patch });
  };
  const p = form.provider === '' ? null : providers[form.provider];
  const target = (f: AIForm) => (f.provider === 'anthropic' && f.base_url === '' ? providers.anthropic.baseURL : f.base_url);
  const sameTarget = form.provider === stored.provider && target(form) === stored.base_url;
  const ready = aiFormReady(form, stored.api_key_set, sameTarget);
  const problems = save.error instanceof ApiError ? problemsOf(save.error) : [];

  return (
    <section className="panel-card" aria-labelledby="ai-model-title">
      <h2 id="ai-model-title">Model</h2>
      <p className="muted small">
        {stored.enabled ? (
          <>
            On: <span className="mono">{stored.model}</span> at <span className="mono">{stored.base_url}</span>, API key{' '}
            {stored.api_key_set ? 'set' : 'not set'}.
          </>
        ) : (
          'Off. Hearth works fully without it.'
        )}{' '}
        The key is write-only: the hub never shows it again.
      </p>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(aiEditBody(form, stored.revision));
        }}
      >
        <label className="field">
          Provider
          <select
            value={form.provider}
            onChange={(e) => {
              set({ provider: e.target.value as AIProvider | '', base_url: '', model: '', api_key: '' });
            }}
          >
            <option value="">Off</option>
            <option value="openai">{providers.openai.label}</option>
            <option value="anthropic">{providers.anthropic.label}</option>
          </select>
        </label>
        {p ? (
          <>
            <p className="muted small">{p.hint}</p>
            <label className="field">
              Address
              <input
                type="url"
                className="mono"
                placeholder={p.baseURL}
                required={form.provider === 'openai'}
                value={form.base_url}
                onChange={(e) => {
                  set({ base_url: e.target.value });
                }}
              />
            </label>
            <label className="field">
              Model
              <input
                type="text"
                className="mono"
                placeholder={p.model}
                required={form.provider === 'openai'}
                value={form.model}
                onChange={(e) => {
                  set({ model: e.target.value });
                }}
              />
            </label>
            <label className="field">
              API key {p.keyNeeded ? '' : '(optional)'}
              <input
                type="password"
                autoComplete="off"
                placeholder={stored.api_key_set && sameTarget ? 'Stored: leave empty to keep it' : ''}
                value={form.api_key}
                onChange={(e) => {
                  set({ api_key: e.target.value });
                }}
              />
            </label>
            {stored.api_key_set && sameTarget && !p.keyNeeded ? (
              <label className="check">
                <input
                  type="checkbox"
                  checked={form.clear_api_key}
                  onChange={(e) => {
                    set({ clear_api_key: e.target.checked });
                  }}
                />{' '}
                Remove the stored key
              </label>
            ) : null}
            {stored.api_key_set && !sameTarget ? (
              <p className="muted small">The stored key is not sent to a new provider or address: enter it again.</p>
            ) : null}
          </>
        ) : null}
        {problems.length > 0 ? (
          <ProblemList problems={problems} />
        ) : save.isError ? (
          <p className="error" role="alert">
            {save.error.message}
          </p>
        ) : null}
        {save.isSuccess ? (
          <p className="pill pill-ok" role="status">
            Saved
          </p>
        ) : null}
        <div className="settings-actions">
          <button className="btn btn-primary" type="submit" disabled={save.isPending || !ready}>
            {save.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>
    </section>
  );
}
