import { Fragment, useDeferredValue, useEffect, useState } from 'react';
import type { ActionClass, AuditEntry, AuditFilter, Decision } from '../api/client.ts';
import { useAudit, useDevices } from '../api/hooks.ts';
import { displayName, relativeTime } from '../format.ts';

const actorKinds: { id: string; label: string }[] = [
  { id: 'admin', label: 'CLI (admin)' },
  { id: 'web', label: 'Web UI' },
  { id: 'automation', label: 'Automation' },
  { id: 'token', label: 'Enrolling agent' },
  { id: 'join_token', label: 'Joining hub' },
  { id: 'hub', label: 'Cluster hub' },
  { id: 'approval_link', label: 'Approval link' },
  { id: 'guest', label: 'Panel guest' },
];

const ranges: { id: string; label: string; ms?: number }[] = [
  { id: '1h', label: 'Last hour', ms: 3_600_000 },
  { id: '24h', label: 'Last 24 hours', ms: 86_400_000 },
  { id: '7d', label: 'Last 7 days', ms: 7 * 86_400_000 },
  { id: '30d', label: 'Last 30 days', ms: 30 * 86_400_000 },
  { id: 'all', label: 'All time' },
];

const decisionLabel: Record<Decision, string> = { allow: 'Allowed', confirm: 'Held', deny: 'Denied' };
const decisionTone: Record<Decision, string> = { allow: 'pill-ok', confirm: 'pill-warn', deny: 'pill-bad' };
const classTone: Record<ActionClass, string> = { read: 'pill-muted', safe: 'pill-ok', dangerous: 'pill-bad' };

interface Filters {
  range: string;
  /** RFC 3339, fixed when the range was chosen so the query stays put. */
  since?: string;
  actor_kind: string;
  actor: string;
  action: string;
  class: string;
  decision: string;
  device: string;
}

const initial: Filters = { range: '24h', actor_kind: '', actor: '', action: '', class: '', decision: '', device: '' };

function sinceFor(range: string): string | undefined {
  const ms = ranges.find((r) => r.id === range)?.ms;
  return ms === undefined ? undefined : new Date(Date.now() - ms).toISOString();
}

/** The current time, ticking every intervalMs, for relative times. */
function useNow(intervalMs: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => {
      setNow(Date.now());
    }, intervalMs);
    return () => {
      clearInterval(t);
    };
  }, [intervalMs]);
  return now;
}

function Select(props: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { id: string; label: string }[];
  any?: string;
}) {
  return (
    <label className="filter">
      <span>{props.label}</span>
      <select
        value={props.value}
        onChange={(e) => {
          props.onChange(e.target.value);
        }}
      >
        {props.any !== undefined ? <option value="">{props.any}</option> : null}
        {props.options.map((o) => (
          <option key={o.id} value={o.id}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

/** The audit log: every policy decision, newest first, with filters. */
export function AuditPage() {
  const [filters, setFilters] = useState<Filters>(() => ({ ...initial, since: sinceFor(initial.range) }));
  const [open, setOpen] = useState<number>();
  const actor = useDeferredValue(filters.actor.trim());
  const devices = useDevices();

  const query: AuditFilter = {
    actor_kind: filters.actor_kind || undefined,
    actor: actor || undefined,
    action: filters.action || undefined,
    class: (filters.class || undefined) as ActionClass | undefined,
    decision: (filters.decision || undefined) as Decision | undefined,
    device: filters.device || undefined,
    since: filters.since,
  };
  const audit = useAudit(query);
  const entries = audit.data?.pages.flatMap((p) => p.entries) ?? [];
  const actions = audit.data?.pages[0]?.actions ?? [];
  const now = useNow(30_000);

  const set = (patch: Partial<Filters>) => {
    setFilters((f) => ({ ...f, ...patch }));
  };
  const filtered = Object.entries(filters).some(([k, v]) => k !== 'since' && v !== initial[k as keyof Filters]);

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="muted">Every action from the CLI, the web UI and automations, and what policy decided.</p>
        </div>
      </div>

      <div className="filters" role="search" aria-label="Audit log filters">
        <Select
          label="Time"
          value={filters.range}
          options={ranges}
          onChange={(v) => {
            set({ range: v, since: sinceFor(v) });
          }}
        />
        <Select
          label="Actor"
          value={filters.actor_kind}
          any="Anyone"
          options={actorKinds}
          onChange={(v) => {
            set({ actor_kind: v });
          }}
        />
        <label className="filter">
          <span>Actor id</span>
          <input
            type="search"
            placeholder="e.g. backup or 192.168…"
            value={filters.actor}
            onChange={(e) => {
              set({ actor: e.target.value });
            }}
          />
        </label>
        <Select
          label="Action"
          value={filters.action}
          any="Any action"
          options={actions.map((a) => ({ id: a, label: a }))}
          onChange={(v) => {
            set({ action: v });
          }}
        />
        <Select
          label="Class"
          value={filters.class}
          any="Any class"
          options={[
            { id: 'read', label: 'Read' },
            { id: 'safe', label: 'Safe' },
            { id: 'dangerous', label: 'Dangerous' },
          ]}
          onChange={(v) => {
            set({ class: v });
          }}
        />
        <Select
          label="Decision"
          value={filters.decision}
          any="Any decision"
          options={[
            { id: 'allow', label: 'Allowed' },
            { id: 'confirm', label: 'Held for approval' },
            { id: 'deny', label: 'Denied' },
          ]}
          onChange={(v) => {
            set({ decision: v });
          }}
        />
        <Select
          label="Device"
          value={filters.device}
          any="Any device"
          options={(devices.data ?? []).map((d) => ({ id: d.id, label: displayName(d) }))}
          onChange={(v) => {
            set({ device: v });
          }}
        />
        {filtered ? (
          <button
            className="btn btn-ghost btn-small filters-clear"
            type="button"
            onClick={() => {
              setFilters({ ...initial, since: sinceFor(initial.range) });
            }}
          >
            Clear
          </button>
        ) : null}
      </div>

      {audit.isError ? (
        <div className="error-box" role="alert">
          Could not load the audit log: {audit.error.message}
        </div>
      ) : audit.isPending ? (
        <p className="muted">Loading the audit log…</p>
      ) : entries.length === 0 ? (
        <div className="empty">
          <h2>Nothing here</h2>
          <p className="muted">No audit entries match these filters.</p>
        </div>
      ) : (
        <>
          <div className="table-wrap">
            <table className="devices audit">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Class</th>
                  <th>Target</th>
                  <th>Decision</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <Fragment key={e.id}>
                    <Row
                      entry={e}
                      now={now}
                      open={open === e.id}
                      onToggle={() => {
                        setOpen(open === e.id ? undefined : e.id);
                      }}
                    />
                    {open === e.id ? (
                      <tr className="audit-detail">
                        <td colSpan={7}>
                          <pre className="mono">{JSON.stringify(e.detail, null, 2)}</pre>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
          {audit.hasNextPage ? (
            <div className="load-more">
              <button
                className="btn btn-ghost"
                type="button"
                disabled={audit.isFetchingNextPage}
                onClick={() => {
                  void audit.fetchNextPage();
                }}
              >
                {audit.isFetchingNextPage ? 'Loading…' : 'Load older entries'}
              </button>
            </div>
          ) : null}
        </>
      )}
    </main>
  );
}

function Row({ entry: e, now, open, onToggle }: { entry: AuditEntry; now: number; open: boolean; onToggle: () => void }) {
  return (
    <tr
      tabIndex={0}
      aria-expanded={open}
      onClick={onToggle}
      onKeyDown={(ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          onToggle();
        }
      }}
    >
      <td className="muted" title={new Date(e.ts).toLocaleString()}>
        {relativeTime(e.ts, now)}
      </td>
      <td className="wrap">
        <span className="muted">{e.actor_kind}/</span>
        {e.actor_id}
      </td>
      <td className="mono">{e.action}</td>
      <td>{e.class ? <span className={`pill ${classTone[e.class]}`}>{e.class}</span> : <span className="muted">—</span>}</td>
      <td className="mono wrap">{e.target || <span className="muted">—</span>}</td>
      <td>
        <span className="decision-cell">
          <span className={`pill ${decisionTone[e.decision]}`}>{decisionLabel[e.decision]}</span>
          {e.result.startsWith('dry-run') ? <span className="pill pill-muted">dry run</span> : null}
        </span>
      </td>
      <td className="wrap audit-result">
        <Result result={e.result} />
      </td>
    </tr>
  );
}

/** What became of an action. The hub records a started action before it runs. */
function Result({ result }: { result: string }) {
  if (result === 'started') {
    return (
      <span
        className="pill pill-warn"
        title="The action is still running, the hub stopped before it could report the result, or a cluster lost its leader while writing this entry and the action was refused. It may also have run with its result unrecorded."
      >
        No outcome recorded
      </span>
    );
  }
  if (result === 'read allowed') {
    return (
      <span
        className="muted"
        title="Reads are recorded before they run, and only a read that fails records a result. This does not prove the read succeeded: an interrupted read looks the same."
      >
        Read allowed
      </span>
    );
  }
  return result || <span className="muted">—</span>;
}
