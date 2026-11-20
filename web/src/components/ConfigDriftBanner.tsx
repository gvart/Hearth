import type { ConfigDrift, ConfigDriftItem } from '../api/client.ts';
import { useConfigDrift } from '../api/hooks.ts';

const docsURL = 'https://github.com/gvart/hearth/blob/main/docs/cluster.md#host-flag-drift';

const itemLabels: Record<string, string> = {
  host_flags: '--allow-dangerous-automation',
};

function itemLabel(item: string) {
  return itemLabels[item] ?? item;
}

/** The hubs that could not be compared, with why when the hub says. */
function unknownHubs(report: ConfigDrift) {
  const ids = new Set(report.items.flatMap((i) => i.unknown));
  const reasons: Record<string, string> = {
    unreachable: 'not answering',
    older_version: 'older version',
    not_reported: 'not reported yet',
  };
  return [...ids].sort().map((id) => {
    const reason = report.hubs.find((h) => h.id === id)?.reason;
    return reason ? `${id} (${reasons[reason] ?? reason})` : id;
  });
}

function DriftLine({ item }: { item: ConfigDriftItem }) {
  return (
    <li>
      <code>{itemLabel(item.item)}</code> differs: {item.groups.map((g) => g.join(', ')).join(' vs ')}
    </li>
  );
}

/**
 * Warns when the hubs of a cluster run with different host flags, the grants
 * each host sets for itself, which a failover would then change. Policy,
 * notification channels, automations and runbooks are in the replicated store
 * and cannot differ. It names items and hubs only: the API holds no digests.
 */
export function ConfigDriftBanner() {
  const report = useConfigDrift().data;
  if (!report) {
    return null;
  }
  const differing = report.items.filter((i) => i.status === 'differs');
  const unknown = unknownHubs(report);
  if (differing.length === 0 && unknown.length === 0) {
    return null;
  }
  const hubsLine = unknown.length > 0 ? <>Could not compare {unknown.join(', ')}.</> : null;

  if (differing.length === 0) {
    return (
      <aside className="drift-banner drift-banner-quiet" aria-label="Hub host flags">
        <p className="small muted">Host flag check incomplete. {hubsLine}</p>
      </aside>
    );
  }
  return (
    <aside className="drift-banner" role="alert" aria-label="Hub host flags">
      <p>
        <strong>Hubs run with different host flags.</strong> Policy and automations are the same on every hub, but
        these per-host grants are not: a failover changes which automations may act.{' '}
        <a href={docsURL} target="_blank" rel="noreferrer">
          How to resolve this
        </a>
      </p>
      <ul>
        {differing.map((i) => (
          <DriftLine key={i.item} item={i} />
        ))}
      </ul>
      {hubsLine ? <p className="small muted">{hubsLine}</p> : null}
    </aside>
  );
}
