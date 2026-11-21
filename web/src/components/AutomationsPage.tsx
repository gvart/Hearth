import { useEffect, useState } from 'react';
import { useAutomations } from '../api/automations.ts';
import { AutomationEditor } from './AutomationEditor.tsx';
import './AutomationsPage.css';
import { Tip } from './Tip.tsx';

const editRoute = '#/automations/edit/';
const newRoute = '#/automations/new';

/** The automations list, or the editor the URL hash opens. */
export default function AutomationsPage() {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onHash = () => {
      setHash(window.location.hash);
    };
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('hashchange', onHash);
    };
  }, []);

  if (hash === newRoute) {
    return <AutomationEditor key="new" />;
  }
  if (hash.startsWith(editRoute)) {
    const id = decodeURIComponent(hash.slice(editRoute.length));
    return <AutomationEditor key={id} id={id} />;
  }
  return <AutomationList />;
}

function AutomationList() {
  const automations = useAutomations();
  const list = automations.data ?? [];

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>
            Automations <Tip id="automations" />
          </h1>
          {automations.data ? (
            <p className="muted">
              {list.length === 0 ? 'No automations yet' : `${String(list.length)} file${list.length === 1 ? '' : 's'}`}
            </p>
          ) : null}
        </div>
        <a className="btn btn-primary" href={newRoute}>
          New automation
        </a>
      </div>

      {automations.isError ? (
        <div className="error-box" role="alert">
          Could not load automations: {automations.error.message}
        </div>
      ) : automations.isPending ? (
        <p className="muted">Loading automations…</p>
      ) : list.length === 0 ? (
        <div className="empty">
          <h2>Automate something</h2>
          <p className="muted">
            An automation is a YAML file every hub of the cluster holds. Create one here, or import files with{' '}
            <code>hearth config import</code>.
          </p>
        </div>
      ) : (
        <ul className="auto-list">
          {list.map((a) => (
            <li key={a.file} className="auto-list-item">
              <div className="auto-list-main">
                {a.id ? (
                  <a className="name mono" href={`${editRoute}${encodeURIComponent(a.id)}`}>
                    {a.id}
                  </a>
                ) : (
                  <span className="name mono">{a.file}</span>
                )}
                {a.description ? <span className="muted small">{a.description}</span> : null}
                {a.problems.map((p) => (
                  <span key={`${String(p.line)}:${p.message}`} className="error">
                    {p.line > 0 ? `Line ${String(p.line)}: ` : ''}
                    {p.message}
                  </span>
                ))}
              </div>
              <span className="muted small auto-list-meta">
                {a.problems.length > 0
                  ? 'Invalid'
                  : `${String(a.triggers)} trigger${a.triggers === 1 ? '' : 's'}, ${String(a.actions)} action${a.actions === 1 ? '' : 's'}`}
              </span>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
