import { ApiError } from '../api/client.ts';
import type { useNetworkScan } from '../api/hooks.ts';
import { scanSummary } from '../networkscan.ts';

type Scan = ReturnType<typeof useNetworkScan>;

/** Starts a scan of the hub's network; disabled while one runs. */
export function NetworkScanButton({ scan, primary = false }: { scan: Scan; primary?: boolean }) {
  const running = scan.state.running || scan.start.isPending;
  return (
    <button
      className={primary ? 'btn btn-primary' : 'btn'}
      type="button"
      disabled={running}
      onClick={() => {
        scan.start.mutate();
      }}
    >
      {running ? 'Scanning…' : 'Scan my network'}
    </button>
  );
}

/** How the last scan asked for from this UI went, or why it could not start. */
export function NetworkScanResult({ scan }: { scan: Scan }) {
  const { state, start } = scan;
  let text: string | undefined;
  if (start.error && !(start.error instanceof ApiError && start.error.code === 'scan_running')) {
    text = `Could not scan: ${start.error.message}`;
  } else if (state.running) {
    text = 'Scanning your network…';
  } else if (state.done) {
    text = scanSummary(state.done);
  }
  return (
    <p className="muted" role="status">
      {text}
    </p>
  );
}
