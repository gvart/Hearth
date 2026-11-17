import type { DeviceStatus } from '../api/client.ts';
import { statusLabel } from '../format.ts';

export function StatusDot({ status }: { status: DeviceStatus }) {
  const label = statusLabel(status);
  return <span className={`dot dot-${status}`} role="img" aria-label={label} title={label} />;
}
