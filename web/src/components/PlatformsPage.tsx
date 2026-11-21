import { useEffect, useState } from 'react';
import type { KubeCluster } from '../api/client.ts';
import { useKubeClusters } from '../api/hooks.ts';
import { useProxmoxServers, type ProxmoxServer } from '../api/proxmox.ts';
import { connectPlatformHash } from '../nav.ts';
import {
  kindLabel,
  platformCards,
  platformHash,
  platformSummary,
  platformsHash,
  stateLabel,
  type PlatformCard,
  type PlatformKind,
  type PlatformState,
} from '../platforms.ts';
import { AddClusterDialog } from './AddClusterDialog.tsx';
import { AddProxmoxDialog } from './AddProxmoxDialog.tsx';
import { Modal } from './Modal.tsx';
import './PanelsPage.css';
import './PlatformsPage.css';

const stateDot: Record<PlatformState, string> = {
  connecting: 'dot-unknown',
  connected: 'dot-online',
  unreachable: 'dot-error',
};

/** What connecting each kind takes and gives, on the dialog that offers them. */
const kinds: { kind: PlatformKind; mark: string; needs: string }[] = [
  {
    kind: 'kubernetes',
    mark: 'K8S',
    needs: 'Paste a kubeconfig from Talos, k3s or kind. Hearth reads nodes, workloads, pods, events and logs.',
  },
  {
    kind: 'proxmox',
    mark: 'PVE',
    needs: 'Add a Proxmox VE API token. Hearth reads hosts, VMs, LXCs and storage.',
  },
];

const mark: Record<PlatformKind, string> = { kubernetes: 'K8S', proxmox: 'PVE' };

/**
 * The clusters and servers Hearth reads next to its own devices: Kubernetes
 * clusters and Proxmox servers, each a card that opens its page.
 */
export function PlatformsPage() {
  const clusters = useKubeClusters();
  const servers = useProxmoxServers();
  // The chooser is open while the URL says so (#/platforms/connect), so a link can open it.
  const choosing = useChoosing();
  const [kind, setKind] = useState<PlatformKind | null>(null);
  const cards = platformCards(clusters.data ?? [], servers.data ?? []);
  const loading = clusters.isPending || servers.isPending;
  const close = () => {
    setKind(null);
    if (window.location.hash === connectPlatformHash) {
      window.location.hash = platformsHash;
    }
  };
  const opened = (k: PlatformKind) => (p: KubeCluster | ProxmoxServer) => {
    setKind(null);
    window.location.hash = platformHash(k, p.id);
  };

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Platforms</h1>
          {loading ? null : <p className="muted">{platformSummary(cards)}</p>}
        </div>
        <a className="btn btn-primary" href={connectPlatformHash}>
          <span aria-hidden="true">＋</span> Connect platform
        </a>
      </div>

      {clusters.isError ? (
        <div className="error-box" role="alert">
          Could not load the Kubernetes clusters: {clusters.error.message}
        </div>
      ) : null}
      {servers.isError ? (
        <div className="error-box" role="alert">
          Could not load the Proxmox servers: {servers.error.message}
        </div>
      ) : null}

      {cards.length > 0 ? (
        <div className="panel-list">
          {cards.map((c) => (
            <PlatformLink key={`${c.kind}/${c.id}`} card={c} />
          ))}
        </div>
      ) : loading ? (
        <p className="muted">Loading platforms…</p>
      ) : clusters.isError || servers.isError ? null : (
        <div className="empty">
          <h2>Adopt what you already run</h2>
          <p className="muted">
            Connect a Kubernetes cluster or a Proxmox server to see it next to your devices. Hearth only changes something
            when you ask it to, and installs nothing there.
          </p>
          <a className="btn btn-primary" href={connectPlatformHash}>
            Connect platform
          </a>
        </div>
      )}

      {kind === 'kubernetes' ? (
        <AddClusterDialog onClose={close} onAdded={opened('kubernetes')} />
      ) : kind === 'proxmox' ? (
        <AddProxmoxDialog onClose={close} onAdded={opened('proxmox')} />
      ) : choosing ? (
        <Modal className="dialog" labelledBy="connect-title" onClose={close}>
          <header className="dialog-head">
            <h2 id="connect-title">Connect a platform</h2>
            <button className="btn btn-ghost icon-btn" type="button" aria-label="Close" onClick={close}>
              ✕
            </button>
          </header>
          <div className="platform-kinds">
            {kinds.map((k) => (
              <button
                key={k.kind}
                type="button"
                className="platform-kind"
                onClick={() => {
                  setKind(k.kind);
                }}
              >
                <span className="platform-mark" aria-hidden="true">
                  {k.mark}
                </span>
                <span className="platform-kind-text">
                  <span className="name">{kindLabel[k.kind]}</span>
                  <span className="muted small">{k.needs}</span>
                </span>
              </button>
            ))}
          </div>
        </Modal>
      ) : null}
    </main>
  );
}

function useChoosing(): boolean {
  const [choosing, setChoosing] = useState(() => window.location.hash === connectPlatformHash);
  useEffect(() => {
    const onHash = () => {
      setChoosing(window.location.hash === connectPlatformHash);
    };
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('hashchange', onHash);
    };
  }, []);
  return choosing;
}

function PlatformLink({ card }: { card: PlatformCard }) {
  return (
    <a className="panel-card platform-card" href={card.hash}>
      <span className="platform-head">
        <span className="platform-mark" aria-hidden="true">
          {mark[card.kind]}
        </span>
        <span className="platform-kind-text">
          <span className="name status-line">
            <span className={`dot ${stateDot[card.state]}`} role="img" aria-label={stateLabel[card.state]} />
            {card.name}
          </span>
          <span className="muted small">{kindLabel[card.kind]}</span>
        </span>
      </span>
      <span className="muted small mono platform-address">{card.address}</span>
      <span className="small">
        {card.state === 'unreachable' ? `${stateLabel[card.state]}: ${card.error || 'no answer'}` : card.line}
      </span>
    </a>
  );
}
