import { useBeszelSystems, useKubeClusters, useNetworkHosts, useTalosNodes } from '../api/hooks.ts';
import { usePlugins } from '../api/plugins.ts';
import { useProxmoxServers } from '../api/proxmox.ts';
import { docsURL, integrationSummary, integrations, stateWord, type Integration, type IntegrationState } from '../integrations.ts';
import './PanelsPage.css';
import './IntegrationsPage.css';

const pill: Record<IntegrationState, string> = {
  on: 'pill-ok',
  off: 'pill-muted',
  trouble: 'pill-bad',
  host: 'pill-muted',
};

/**
 * What the hub reads besides its own agents, on one page: which integrations
 * are on, what each gives, where its data shows and how it is set up. It only
 * reads what the other pages read; an integration turned on by a hub flag the
 * API does not report says so instead of guessing.
 */
export function IntegrationsPage() {
  const clusters = useKubeClusters();
  const servers = useProxmoxServers();
  const talos = useTalosNodes();
  const beszel = useBeszelSystems();
  const plugins = usePlugins();
  const hosts = useNetworkHosts();
  const list = integrations({
    clusters: clusters.data,
    servers: servers.data,
    talos: talos.data,
    beszel: beszel.data,
    plugins: plugins.data?.plugins,
    hosts: hosts.data,
  });
  const loading = [clusters, servers, talos, beszel, plugins, hosts].some((q) => q.isPending);

  return (
    <main className="content">
      <div className="page-head">
        <div>
          <h1>Integrations</h1>
          <p className="muted">{loading ? 'Reading what the hub is connected to…' : integrationSummary(list)}</p>
        </div>
      </div>
      <p className="muted small integrations-lead">
        Hearth adopts what you already run. Kubernetes and Proxmox are connected here in the UI; the others are turned on
        where the hub is started, with a flag or an environment variable.
      </p>
      <ul className="panel-list integrations">
        {list.map((i) => (
          <IntegrationCard key={i.id} integration={i} />
        ))}
      </ul>
    </main>
  );
}

function IntegrationCard({ integration: i }: { integration: Integration }) {
  return (
    <li className="panel-card">
      <div className="panel-card-head">
        <h2>{i.name}</h2>
        <span className={`pill ${pill[i.state]}`}>{stateWord[i.state]}</span>
      </div>
      <p className="muted small">{i.gives}</p>
      <p className="small">{i.detail}</p>
      <p className="small integration-links">
        {i.where ? <a href={i.where.hash}>Shown on {i.where.label}</a> : null}
        <a href={docsURL(i.docs)} target="_blank" rel="noreferrer">
          Set it up
        </a>
      </p>
    </li>
  );
}
