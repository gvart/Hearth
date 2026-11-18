import { useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { LogLine } from '../api/client.ts';

interface LogViewerProps {
  lines: LogLine[];
  /** Lines received so far, dropped ones included; counts what a pause holds back. Live views only. */
  total?: number;
  /** A live view can be paused; a snapshot cannot. */
  live: boolean;
  /** Controls of the source, shown before the viewer's own. */
  controls?: ReactNode;
  /** A line under the toolbar: connection state, errors. */
  status?: ReactNode;
  label: string;
}

/** Time of day of an RFC 3339 timestamp, with milliseconds. */
function timeOf(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime())
    ? ''
    : d.toLocaleTimeString(undefined, { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

/**
 * The log viewer shared by device logs and Kubernetes pod logs: filter,
 * follow (keep the newest line in view) and, for a live stream, pause
 * (freeze the view while lines keep arriving). Give it a new key for a new
 * source.
 */
export function LogViewer({ lines, total, live, controls, status, label }: LogViewerProps) {
  const [filter, setFilter] = useState('');
  const [follow, setFollow] = useState(true);
  const [paused, setPaused] = useState<{ lines: LogLine[]; total: number } | null>(null);
  const pre = useRef<HTMLPreElement>(null);

  const shown = paused?.lines ?? lines;
  const visible = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return f ? shown.filter((l) => l.text.toLowerCase().includes(f)) : shown;
  }, [shown, filter]);
  const held = paused && total !== undefined ? total - paused.total : 0;

  useLayoutEffect(() => {
    if (follow && pre.current) {
      pre.current.scrollTop = pre.current.scrollHeight;
    }
  }, [visible, follow]);

  return (
    <>
      <div className="logs-bar">
        {controls}
        <input
          className="logs-filter"
          type="search"
          placeholder="Filter"
          aria-label="Filter lines"
          value={filter}
          onChange={(e) => {
            setFilter(e.target.value);
          }}
        />
        <label className="logs-toggle">
          <input
            type="checkbox"
            checked={follow}
            onChange={(e) => {
              setFollow(e.target.checked);
            }}
          />
          Follow
        </label>
        {live ? (
          <button
            className="btn btn-small"
            type="button"
            aria-pressed={paused !== null}
            onClick={() => {
              setPaused(paused ? null : { lines, total: total ?? lines.length });
            }}
          >
            {paused ? `Resume${held > 0 ? ` (${String(held)} new)` : ''}` : 'Pause'}
          </button>
        ) : null}
      </div>
      <p className="muted small logs-status" aria-live="polite">
        {status}
        {status ? ' · ' : ''}
        {filter.trim() ? `${String(visible.length)} of ${String(shown.length)} lines` : `${String(shown.length)} lines`}
        {paused ? ' · paused' : ''}
      </p>
      <pre ref={pre} className="logs" aria-label={label} tabIndex={0}>
        {visible.length === 0 ? (
          <span className="muted">{shown.length === 0 ? 'No lines yet.' : 'No line matches the filter.'}</span>
        ) : (
          visible.map((l, i) => (
            <div key={i} className="log-line">
              {l.ts ? <span className="log-ts">{timeOf(l.ts)} </span> : null}
              {l.text}
            </div>
          ))
        )}
      </pre>
    </>
  );
}
