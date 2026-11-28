// The web terminal's connection to the hub: a WebSocket on
// /api/v1/devices/{id}/shell, authenticated by the session cookie. Binary
// messages carry the shell's output and the keyboard's input; text messages
// are JSON (ShellMessageJSON in internal/hub/shell.go).

/** The largest input message sent; the hub refuses more than 64 KiB. */
const maxInputMessage = 32 * 1024;

/** How to set up what terminals need. */
export const terminalHttpsDocs = 'https://github.com/gvart/hearth/blob/main/docs/https.md';

const launchKey = 'hearth.terminal.launch';
/** How long after a click on the Terminal button its tab may connect by itself. */
const launchWindowMs = 10_000;

/** The hub serves terminals only over HTTPS, or to a browser on the hub itself. */
export function terminalTransportAllowed(): boolean {
  const { protocol, hostname } = window.location;
  return protocol === 'https:' || ['localhost', '127.0.0.1', '[::1]'].includes(hostname);
}

/** Records that the user asked for a terminal, recorded for a runbook or not, for the tab about to open. */
export function markTerminalLaunch(deviceId: string, record = false): void {
  try {
    localStorage.setItem(launchKey, JSON.stringify({ deviceId, at: Date.now(), record }));
  } catch {
    // Without storage the new tab asks for a click instead.
  }
}

/**
 * Whether the user just asked for this terminal, and whether to record it for
 * a runbook; null if not. Anything else that loads the page, such as a link
 * from elsewhere or a reload, must not start a shell.
 */
export function consumeTerminalLaunch(deviceId: string): { record: boolean } | null {
  try {
    const raw = localStorage.getItem(launchKey);
    localStorage.removeItem(launchKey);
    if (!raw) {
      return null;
    }
    const launch = JSON.parse(raw) as { deviceId?: string; at?: number; record?: boolean };
    if (launch.deviceId !== deviceId || Date.now() - (launch.at ?? 0) >= launchWindowMs) {
      return null;
    }
    return { record: launch.record === true };
  } catch {
    return null;
  }
}

/**
 * Whether data is the terminal answering the shell by itself (device status,
 * cursor position, focus, colour and settings reports), not someone typing.
 */
export function isAutoReply(data: string): boolean {
  return data.startsWith('\u001b') && /^(?:\[[?>]?[\d;]*[cnRt]|\[[IO]|\].*|P.*)$/su.test(data.slice(1));
}

export interface TerminalSize {
  rows: number;
  cols: number;
}

/** What the hub says about a terminal session. */
export type TerminalEvent =
  /** Policy holds the session until an operator approves it. */
  | { type: 'pending'; approval: string; expires: string }
  /** recording is set, by the hub, only for a session it records for a runbook. */
  | { type: 'started'; shell: string; idle_timeout: number; max_duration: number; recording?: string; record_limit?: number }
  /** The recording reached its limit: the rest of the session is not recorded. */
  | { type: 'recording_full'; record_limit: number }
  | { type: 'exit'; exit_code: number; reason: string }
  | {
      type: 'error';
      code: 'forbidden' | 'reauth_required' | 'ai_off' | 'not_connected' | 'failed';
      reason: string;
    }
  /** The connection dropped without the hub saying why. */
  | { type: 'disconnected' };

export interface TerminalConnection {
  /** Sends keyboard input. */
  send(data: string): void;
  resize(size: TerminalSize): void;
  /** Ends the session: the agent kills the shell. */
  close(): void;
}

/**
 * Opens a terminal on the device. With record, the hub records what the
 * terminal shows for a runbook draft, if policy allows it; refused, no
 * shell opens at all.
 */
export function openTerminal(
  deviceId: string,
  size: TerminalSize,
  onOutput: (data: Uint8Array) => void,
  onEvent: (ev: TerminalEvent) => void,
  record = false,
): TerminalConnection {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const q = new URLSearchParams({ rows: String(size.rows), cols: String(size.cols) });
  if (record) {
    q.set('record', '1');
  }
  const ws = new WebSocket(
    `${scheme}//${window.location.host}/api/v1/devices/${encodeURIComponent(deviceId)}/shell?${q.toString()}`,
  );
  ws.binaryType = 'arraybuffer';
  const encoder = new TextEncoder();
  let ended = false;
  // Nothing is sent until the shell runs: a session held for approval has
  // nobody to type to, and the hub drops what comes before the start.
  let started = false;
  let latest = size;

  ws.onmessage = (msg: MessageEvent<ArrayBuffer | string>) => {
    if (typeof msg.data !== 'string') {
      onOutput(new Uint8Array(msg.data));
      return;
    }
    const ev = JSON.parse(msg.data) as TerminalEvent;
    if (ev.type === 'exit' || ev.type === 'error') {
      ended = true;
    }
    if (ev.type === 'started') {
      started = true;
      if (latest.rows !== size.rows || latest.cols !== size.cols) {
        ws.send(JSON.stringify({ type: 'resize', ...latest }));
      }
    }
    onEvent(ev);
  };
  ws.onclose = () => {
    if (!ended) {
      ended = true;
      onEvent({ type: 'disconnected' });
    }
  };

  return {
    send(data) {
      if (!started || ws.readyState !== WebSocket.OPEN) {
        return;
      }
      if (isAutoReply(data)) {
        ws.send(JSON.stringify({ type: 'reply', data }));
        return;
      }
      // A paste can exceed what the hub accepts in one message.
      const bytes = encoder.encode(data);
      for (let i = 0; i < bytes.length; i += maxInputMessage) {
        ws.send(bytes.subarray(i, i + maxInputMessage));
      }
    },
    resize({ rows, cols }) {
      latest = { rows, cols };
      if (started && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', rows, cols }));
      }
    },
    close() {
      ended = true;
      ws.close();
    },
  };
}
