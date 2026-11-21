import { meterTone } from '../devices.ts';

/**
 * A level from 0 to 100 drawn on a ruled line, with its value beside it. It
 * turns yellow from 85% and red from 95%; `plain` keeps it one colour, for a
 * level that is not a warning by itself.
 */
export function Meter({
  label,
  percent,
  plain = false,
}: {
  label: string;
  percent: number | undefined;
  plain?: boolean;
}) {
  const known = percent !== undefined;
  const value = known ? Math.max(0, Math.min(100, Math.round(percent))) : 0;
  const tone = known && !plain ? meterTone(value) : 'ok';
  return (
    <span className={`meter meter-${tone}`}>
      <span className="meter-label">{label}</span>
      <span
        className="meter-track"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={known ? value : undefined}
        aria-valuetext={known ? `${String(value)}%` : 'not reported'}
      >
        <span className="meter-fill" style={{ width: `${String(value)}%` }} />
      </span>
      <span className="meter-value">{known ? `${String(value)}%` : '—'}</span>
    </span>
  );
}
