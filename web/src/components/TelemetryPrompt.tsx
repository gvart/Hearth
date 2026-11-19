import { useSetTelemetry, useTelemetry } from '../api/hooks.ts';
import { telemetryDocsURL, telemetryFields, telemetryView } from '../telemetry.ts';

/** Asks the admin once, after sign-in, whether to share anonymous usage stats. Nothing is sent until yes. */
export function TelemetryPrompt() {
  const view = telemetryView(useTelemetry().data);
  const set = useSetTelemetry();
  if (view !== 'ask') {
    return null;
  }
  return (
    <aside className="telemetry-card" aria-labelledby="telemetry-title">
      <h2 id="telemetry-title">Share anonymous usage stats?</h2>
      <p>
        Help the Hearth project count how many homelabs run it. If you say yes, this hub sends once a week, and nothing
        else:
      </p>
      <ul>
        {telemetryFields.map((f) => (
          <li key={f}>{f}</li>
        ))}
      </ul>
      <p className="small muted">
        No IP addresses, hostnames, device or cluster names, URLs or credentials. You can change this later at the bottom
        of the page.{' '}
        <a href={telemetryDocsURL} target="_blank" rel="noreferrer">
          What is sent, and where
        </a>
      </p>
      {set.isError ? (
        <p className="error-box" role="alert">
          {set.error.message}
        </p>
      ) : null}
      <div className="telemetry-actions">
        <button
          className="btn btn-primary"
          type="button"
          disabled={set.isPending}
          onClick={() => {
            set.mutate(true);
          }}
        >
          Yes, share
        </button>
        <button
          className="btn"
          type="button"
          disabled={set.isPending}
          onClick={() => {
            set.mutate(false);
          }}
        >
          No, thanks
        </button>
      </div>
    </aside>
  );
}

/** The answer, with a toggle to change it; or that the hub turned telemetry off. */
export function TelemetryStatus() {
  const view = telemetryView(useTelemetry().data);
  const set = useSetTelemetry();
  if (view === 'loading' || view === 'ask') {
    return null;
  }
  return (
    <footer className="telemetry-status small muted">
      {view === 'env-off' ? (
        <>Anonymous usage stats are turned off on the hub (HEARTH_TELEMETRY=off).</>
      ) : (
        <>
          Anonymous usage stats: {view === 'on' ? 'shared weekly' : 'off'}.{' '}
          <button
            className="link"
            type="button"
            disabled={set.isPending}
            onClick={() => {
              set.mutate(view !== 'on');
            }}
          >
            {view === 'on' ? 'Stop sharing' : 'Share'}
          </button>
        </>
      )}{' '}
      <a href={telemetryDocsURL} target="_blank" rel="noreferrer">
        What is sent
      </a>
      {set.isError ? <span role="alert"> {set.error.message}</span> : null}
    </footer>
  );
}
