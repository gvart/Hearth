import { useState } from 'react';
import {
  problemsOf,
  useDeleteNotifyChannel,
  useSaveNotifyChannel,
  type NotifyChannelConfig,
  type NotifyChannelEdit,
  type NotifyType,
} from '../api/admin.ts';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { Modal } from './Modal.tsx';
import { ProblemList } from './SettingsPage.tsx';
import './SettingsPage.css';

interface FieldSpec {
  key: 'url' | 'topic' | 'token' | 'bot_token' | 'chat_id';
  label: string;
  hint: string;
  optional?: boolean;
  /** Typed like a password: hidden as it is typed. */
  secret?: boolean;
}

const fields: Record<NotifyType, FieldSpec[]> = {
  ntfy: [
    { key: 'url', label: 'Server URL', hint: 'The ntfy server only, as https://ntfy.sh' },
    { key: 'topic', label: 'Topic', hint: 'On ntfy.sh, pick a long random one or use a token', secret: true },
    { key: 'token', label: 'Access token', hint: 'Optional: an ntfy access token (ntfy token add)', optional: true, secret: true },
  ],
  telegram: [
    { key: 'bot_token', label: 'Bot token', hint: 'From @BotFather', secret: true },
    { key: 'chat_id', label: 'Chat id', hint: 'The chat id, or @channelname', secret: true },
  ],
};

/**
 * Adds or edits a notification channel. Every field is write-only: the hub
 * says only whether it is set, and an empty field keeps the stored value.
 */
export function ChannelDialog({ channel, onClose }: { channel?: NotifyChannelConfig; onClose: () => void }) {
  const isNew = channel === undefined;
  const [name, setName] = useState(channel?.name ?? '');
  const [type, setType] = useState<NotifyType>(channel?.type ?? 'ntfy');
  const [values, setValues] = useState<Record<string, string>>({});
  const [clear, setClear] = useState<string[]>([]);
  const save = useSaveNotifyChannel();
  const problems = problemsOf(save.error);
  // A type change carries nothing over: every field must be typed again.
  const keeps = !isNew && channel.type === type;

  const submit = () => {
    const edit: NotifyChannelEdit = { type, clear: clear.length > 0 ? clear : undefined };
    for (const f of fields[type]) {
      const v = values[f.key]?.trim() ?? '';
      if (v !== '') {
        edit[f.key] = v;
      }
    }
    save.mutate({ name, edit });
  };

  return (
    <Modal className="dialog dialog-wide" labelledBy="channel-title" onClose={onClose}>
      <header className="dialog-head">
        <h2 id="channel-title">{isNew ? 'New channel' : `Edit ${channel.name}`}</h2>
        <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={onClose}>
          ✕
        </button>
      </header>
      {save.isSuccess ? (
        <>
          <div className="ok-box" role="status">
            Saved. Every hub applies it within seconds; send a test to check it.
          </div>
          <div className="form-actions">
            <button className="btn btn-primary" type="button" onClick={onClose}>
              Done
            </button>
          </div>
        </>
      ) : (
        <form
          className="form channel-form"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          {isNew ? (
            <label className="field">
              Name
              <input
                value={name}
                required
                maxLength={64}
                pattern="[a-z0-9_\-]+"
                title="lowercase letters, digits, - and _"
                onChange={(e) => {
                  setName(e.target.value);
                }}
              />
            </label>
          ) : null}
          <label className="field">
            Type
            <select
              value={type}
              onChange={(e) => {
                setType(e.target.value as NotifyType);
                setValues({});
                setClear([]);
              }}
            >
              <option value="ntfy">ntfy</option>
              <option value="telegram">Telegram</option>
            </select>
          </label>
          <p className="muted small">
            Addresses and credentials are write-only: the hub never shows them again, here or anywhere else.{' '}
            {keeps ? 'Leave a field empty to keep what is stored.' : ''}
          </p>
          {fields[type].map((f) => {
            const isSet = keeps && channel.set[f.key] === true && !clear.includes(f.key);
            return (
              <div key={f.key} className="field secret-field">
                <label htmlFor={`channel-${f.key}`}>
                  {f.label}{' '}
                  <span className={`pill secret-state ${isSet ? 'pill-ok' : 'pill-muted'}`}>{isSet ? 'set' : 'not set'}</span>
                </label>
                <input
                  id={`channel-${f.key}`}
                  type={f.secret ? 'password' : 'text'}
                  autoComplete="off"
                  spellCheck={false}
                  value={values[f.key] ?? ''}
                  required={!f.optional && !isSet}
                  placeholder={isSet ? 'Stored: leave empty to keep it' : f.optional ? 'Optional' : ''}
                  onChange={(e) => {
                    setValues({ ...values, [f.key]: e.target.value });
                  }}
                />
                <span className="muted small">{f.hint}</span>
                {f.optional && keeps && channel.set[f.key] === true ? (
                  <label className="small check-row">
                    <input
                      type="checkbox"
                      checked={clear.includes(f.key)}
                      onChange={(e) => {
                        setClear(e.target.checked ? [...clear, f.key] : clear.filter((k) => k !== f.key));
                      }}
                    />{' '}
                    Remove the stored {f.label.toLowerCase()}
                  </label>
                ) : null}
              </div>
            );
          })}
          <p className="muted small">
            Saving is <code>config.import</code>, a dangerous action: it asks for your password, and the whole
            configuration is checked first.
          </p>
          {problems.length > 0 ? (
            <div className="error-box" role="alert">
              <strong>Not saved</strong>
              <ProblemList problems={problems} />
            </div>
          ) : save.isError ? (
            <div className="error-box" role="alert">
              Not saved: {save.error.message}
            </div>
          ) : null}
          {save.isPending ? (
            <p className="muted small" role="status">
              Saving. If policy holds this action, approve it on the Approvals page.
            </p>
          ) : null}
          <div className="form-actions">
            <button className="btn btn-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-danger" type="submit" disabled={save.isPending}>
              {save.isPending ? 'Saving…' : 'Save channel'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

/** Deletes a channel from notify.yaml. */
export function DeleteChannelDialog({ name, onClose }: { name: string; onClose: () => void }) {
  const del = useDeleteNotifyChannel();
  const problems = problemsOf(del.error);
  return (
    <ConfirmDialog
      title={`Delete ${name}`}
      actionClass="dangerous"
      confirmLabel="Delete channel"
      pendingLabel="Deleting…"
      pending={del.isPending}
      error={del.isError ? (problems.length > 0 ? problems.map((p) => p.message).join(' ') : del.error.message) : undefined}
      done={del.isSuccess ? <>Deleted. Every hub stops using it within seconds.</> : undefined}
      asksPassword
      onConfirm={() => {
        del.mutate(name);
      }}
      onClose={onClose}
    >
      <p>
        The channel <strong className="mono">{name}</strong> and its credentials are removed from{' '}
        <code>notify.yaml</code>. A channel an automation or approval notifications still use cannot be deleted.
      </p>
    </ConfirmDialog>
  );
}
