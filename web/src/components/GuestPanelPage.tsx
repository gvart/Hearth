import { useEffect, useState } from 'react';
import { ApiError, type GuestPanel } from '../api/client.ts';
import { useGuestAction, useGuestPanel } from '../api/hooks.ts';
import { relativeTime, statusLabel } from '../format.ts';
import { Logo } from './Logo.tsx';
import { StatusDot } from './StatusDot.tsx';
import './PanelsPage.css';

/** The current time, ticking every interval ms while mounted. */
function useNow(interval: number): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const t = setInterval(() => {
      setNow(Date.now());
    }, interval);
    return () => {
      clearInterval(t);
    };
  }, [interval]);
  return now;
}

/**
 * A panel opened by its share link (/p/<token>), with no session: the link
 * is the credential, for this one panel. With kiosk set (?kiosk=1) it fills
 * the screen, with no navigation and large touch targets, for a wall
 * display. It stays current through the hub's change stream.
 */
export function GuestPanelPage({ token, kiosk }: { token: string; kiosk: boolean }) {
  const panel = useGuestPanel(token);
  const now = useNow(15_000);
  const gone = panel.error instanceof ApiError && panel.error.status === 404;

  useEffect(() => {
    if (panel.data) {
      document.title = `${panel.data.name} · Hearth`;
    }
  }, [panel.data]);

  let body;
  if (panel.isPending) {
    body = <p className="muted">Loading…</p>;
  } else if (gone) {
    body = (
      <div className="error-box" role="alert">
        This panel link is invalid, revoked or expired. Ask for a new one.
      </div>
    );
  } else if (panel.isError && !panel.data) {
    body = (
      <div className="error-box" role="alert">
        Cannot reach the hub: {panel.error.message}
      </div>
    );
  } else {
    body = <GuestWidgets token={token} panel={panel.data} now={now} />;
  }

  return (
    <div className={kiosk ? 'guest kiosk' : 'guest'}>
      {kiosk ? null : (
        <header className="guest-head">
          <Logo size={24} />
          <span className="muted small">Hearth panel</span>
        </header>
      )}
      <main className="guest-main">
        {panel.data && !gone ? <h1 className="guest-title">{panel.data.name}</h1> : null}
        {body}
      </main>
    </div>
  );
}

function GuestWidgets({ token, panel, now }: { token: string; panel: GuestPanel; now: number }) {
  if (panel.widgets.length === 0) {
    return <p className="muted">Nothing on this panel yet.</p>;
  }
  return (
    <div className="guest-grid">
      {panel.widgets.map((w) => (
        <section key={w.id} className={`guest-tile guest-${w.status}`} aria-label={w.name}>
          <div className="guest-tile-head">
            <StatusDot status={w.status} />
            <h2>{w.name}</h2>
          </div>
          <p className="guest-status">
            {statusLabel(w.status)}
            {w.status !== 'online' && w.last_seen ? (
              <span className="muted"> · seen {relativeTime(w.last_seen, now)}</span>
            ) : null}
          </p>
          {w.actions.length > 0 ? (
            <div className="guest-actions">
              {w.actions.map((a) => (
                <GuestButton key={a.id} token={token} widget={w.id} action={a.id} label={a.label} />
              ))}
            </div>
          ) : null}
        </section>
      ))}
    </div>
  );
}

/** What a guest is told about an action that did not run. */
function failure(err: Error): string {
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'denied':
        return 'Not allowed right now.';
      case 'rate_limited':
      case 'busy':
        return 'Please wait a moment and try again.';
      case 'device_offline':
        return 'The device is offline.';
    }
  }
  return 'It did not work.';
}

function GuestButton({ token, widget, action, label }: { token: string; widget: string; action: string; label: string }) {
  const act = useGuestAction(token);
  const [slow, setSlow] = useState(false);

  // An action held for approval answers only once someone decides.
  useEffect(() => {
    if (!act.isPending) {
      return;
    }
    const t = setTimeout(() => {
      setSlow(true);
    }, 3000);
    return () => {
      clearTimeout(t);
    };
  }, [act.isPending]);

  // A result shows for a while, then the button is ready again.
  useEffect(() => {
    if (!act.isSuccess && !act.isError) {
      return;
    }
    const t = setTimeout(() => {
      act.reset();
    }, 8000);
    return () => {
      clearTimeout(t);
    };
  }, [act]);

  return (
    <div className="guest-action">
      <button
        className="btn btn-primary guest-btn"
        type="button"
        disabled={act.isPending}
        onClick={() => {
          setSlow(false);
          act.mutate({ widget, action });
        }}
      >
        {act.isPending ? (slow ? 'Working, or waiting for approval…' : 'Working…') : label}
      </button>
      {act.isSuccess ? (
        <span className="guest-result ok" role="status">
          Done
        </span>
      ) : null}
      {act.isError ? (
        <span className="guest-result bad" role="alert">
          {failure(act.error)}
        </span>
      ) : null}
    </div>
  );
}
