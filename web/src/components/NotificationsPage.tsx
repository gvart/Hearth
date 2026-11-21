import { useState } from 'react';
import { useNotifyConfig, type NotifyChannelConfig } from '../api/admin.ts';
import type { NotifyChannel } from '../api/client.ts';
import { useNotifyChannels, useTestNotifyChannel } from '../api/hooks.ts';
import { ChannelDialog, DeleteChannelDialog } from './ChannelDialog.tsx';

const typeLabel: Record<NotifyChannel['type'], string> = { ntfy: 'ntfy', telegram: 'Telegram' };

/** The hub's notification channels, each with a test-send button, and their editor. */
export function NotificationsPage() {
  const channels = useNotifyChannels();
  // What the editor knows of each channel: which fields are set. Absent on a
  // hub that keeps its configuration in files.
  const config = useNotifyConfig();
  const editable = config.isSuccess;
  const [editing, setEditing] = useState<NotifyChannelConfig | 'new' | null>(null);
  const [deleting, setDeleting] = useState('');
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
        {editable ? (
          <button
            className="btn btn-primary"
            type="button"
            onClick={() => {
              setEditing('new');
            }}
          >
            New channel
          </button>
        ) : null}
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
            Channels are an ntfy topic or a Telegram chat, with their credentials, in the hub&apos;s{' '}
            <code>notify.yaml</code>: add one here, or import the file with <code>hearth config import</code>.
            Automations send to them by name with a <code>notify</code> action.
          </p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="devices kube">
            <thead>
              <tr>
                <th>Channel</th>
                <th>Type</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {list.map((c) => {
                const cfg = config.data?.find((x) => x.name === c.name);
                return (
                  <ChannelRow
                    key={c.name}
                    channel={c}
                    onEdit={
                      cfg
                        ? () => {
                            setEditing(cfg);
                          }
                        : undefined
                    }
                    onDelete={
                      cfg
                        ? () => {
                            setDeleting(c.name);
                          }
                        : undefined
                    }
                  />
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {editing ? (
        <ChannelDialog
          channel={editing === 'new' ? undefined : editing}
          onClose={() => {
            setEditing(null);
          }}
        />
      ) : null}
      {deleting ? (
        <DeleteChannelDialog
          name={deleting}
          onClose={() => {
            setDeleting('');
          }}
        />
      ) : null}
    </main>
  );
}

function ChannelRow({
  channel,
  onEdit,
  onDelete,
}: {
  channel: NotifyChannel;
  onEdit?: () => void;
  onDelete?: () => void;
}) {
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
          {onEdit ? (
            <button className="btn btn-ghost btn-small" type="button" onClick={onEdit}>
              Edit
            </button>
          ) : null}
          {onDelete ? (
            <button className="btn btn-ghost btn-small" type="button" onClick={onDelete}>
              Delete
            </button>
          ) : null}
        </div>
      </td>
    </tr>
  );
}
