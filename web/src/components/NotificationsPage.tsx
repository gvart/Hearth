import type { NotifyChannel } from '../api/client.ts';
import { useNotifyChannels, useTestNotifyChannel } from '../api/hooks.ts';

const typeLabel: Record<NotifyChannel['type'], string> = { ntfy: 'ntfy', telegram: 'Telegram' };

/** The hub's notification channels, each with a test-send button. */
export function NotificationsPage() {
  const channels = useNotifyChannels();
  const list = channels.data ?? [];

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Notifications</h1>
          {channels.data ? (
            <p className="muted">
              {list.length === 0 ? 'No channels yet' : `${String(list.length)} channel${list.length === 1 ? '' : 's'}`}
            </p>
          ) : null}
        </div>
      </div>

      {channels.isError ? (
        <div className="error-box" role="alert">
          Could not load channels: {channels.error.message}
        </div>
      ) : channels.isPending ? (
        <p className="muted">Loading channels…</p>
      ) : list.length === 0 ? (
        <div className="empty">
          <h2>Set up a channel</h2>
          <p className="muted">
            Channels are an ntfy topic or a Telegram chat, configured with their credentials in the hub&apos;s{' '}
            <code>notify.yaml</code> (see <code>hearth hub --notify-config</code>). Automations send to them by name with
            a <code>notify</code> action.
          </p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="devices kube">
            <thead>
              <tr>
                <th>Channel</th>
                <th>Type</th>
                <th aria-label="Test" />
              </tr>
            </thead>
            <tbody>
              {list.map((c) => (
                <ChannelRow key={c.name} channel={c} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

function ChannelRow({ channel }: { channel: NotifyChannel }) {
  const test = useTestNotifyChannel();

  return (
    <tr className="static">
      <td>
        <span className="name mono">{channel.name}</span>
      </td>
      <td className="muted">{typeLabel[channel.type]}</td>
      <td>
        <div className="notify-test">
          {test.isSuccess ? (
            <span className="pill pill-ok" role="status">
              Sent
            </span>
          ) : null}
          {test.isError ? (
            <span className="error" role="alert">
              {test.error.message}
            </span>
          ) : null}
          <button
          className="btn btn-ghost btn-small"
          type="button"
          disabled={test.isPending}
          onClick={() => {
            test.mutate(channel.name);
          }}
        >
            {test.isPending ? 'Sending…' : 'Send test'}
          </button>
        </div>
      </td>
    </tr>
  );
}
