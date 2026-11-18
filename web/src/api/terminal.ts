// The web terminal's connection to the hub: a WebSocket on
// /api/v1/devices/{id}/shell, authenticated by the session cookie. Binary
// messages carry the shell's output and the keyboard's input; text messages
// are JSON (ShellMessageJSON in internal/hub/shell.go).

/** The largest input message sent; the hub refuses more than 64 KiB. */
const maxInputMessage = 32 * 1024;

export interface TerminalSize {
  rows: number;
  cols: number;
}

/** What the hub says about a terminal session. */
export type TerminalEvent =
  /** Policy holds the session until an operator approves it. */
  | { type: 'pending'; approval: string; expires: string }
  | { type: 'started'; shell: string; idle_timeout: number; max_duration: number }
  | { type: 'exit'; exit_code: number; reason: string }
  | { type: 'error'; code: 'forbidden' | 'not_connected' | 'failed'; reason: string }
  /** The connection dropped without the hub saying why. */
  | { type: 'disconnected' };

export interface TerminalConnection {
  /** Sends keyboard input. */
  send(data: string): void;
  resize(size: TerminalSize): void;
  /** Ends the session: the agent kills the shell. */
  close(): void;
}

export function openTerminal(
  deviceId: string,
  size: TerminalSize,
  onOutput: (data: Uint8Array) => void,
  onEvent: (ev: TerminalEvent) => void,
): TerminalConnection {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const q = new URLSearchParams({ rows: String(size.rows), cols: String(size.cols) });
  const ws = new WebSocket(
    `${scheme}//${window.location.host}/api/v1/devices/${encodeURIComponent(deviceId)}/shell?${q.toString()}`,
  );
  ws.binaryType = 'arraybuffer';
  const encoder = new TextEncoder();
  let ended = false;

  ws.onmessage = (msg: MessageEvent<ArrayBuffer | string>) => {
    if (typeof msg.data !== 'string') {
      onOutput(new Uint8Array(msg.data));
      return;
    }
    const ev = JSON.parse(msg.data) as TerminalEvent;
    if (ev.type === 'exit' || ev.type === 'error') {
      ended = true;
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
      if (ws.readyState !== WebSocket.OPEN) {
        return;
      }
      // A paste can exceed what the hub accepts in one message.
      const bytes = encoder.encode(data);
      for (let i = 0; i < bytes.length; i += maxInputMessage) {
        ws.send(bytes.subarray(i, i + maxInputMessage));
      }
    },
    resize({ rows, cols }) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', rows, cols }));
      }
    },
    close() {
      ended = true;
      ws.close();
    },
  };
}
