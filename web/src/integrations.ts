// The Integrations page: what the hub reads besides its own agents, as far as
// the API the UI already has can tell. Kept apart from the components so
// node --test can check it (web/test/integrations.test.mjs).

/**
 * on: in use. off: not set up. trouble: set up but failing. host: set up with a
 * hub flag the API does not report, so the UI cannot tell.
 */
export type IntegrationState = 'on' | 'off' | 'trouble' | 'host';

export const stateWord: Record<IntegrationState, string> = {
  on: 'On',
  off: 'Off',
  trouble: 'Failing',
  host: 'Set on the hub',
};

export interface Integration {
  id: string;
  name: string;
  /** What Hearth gets from it. */
  gives: string;
  state: IntegrationState;
  /** What is known now: counts when on, the error when failing, how to turn it on when off. */
  detail: string;
  /** Where in the UI its data shows. */
  where?: { label: string; hash: string };
  /** The page of the docs that sets it up, under docs/. */
  docs: string;
}

/** A source the hub reads on its own schedule, as /talos/nodes and /beszel/systems report it. */
interface Read {
  status: 'not_configured' | 'connecting' | 'ok' | 'unavailable';
  error?: string;
}

export interface IntegrationInputs {
  clusters?: { state: string }[];
  servers?: { state: string }[];
  esphome?: { state: string }[];
  talos?: Read & { nodes: unknown[] };
  beszel?: Read & { systems: unknown[] };
  plugins?: { state: string }[];
  hosts?: { sources: string[] }[];
}

function count(n: number, one: string, many = `${one}s`): string {
  return `${String(n)} ${n === 1 ? one : many}`;
}

/** A platform kind: on when any is connected, failing when none of them can be reached. */
function connected(list: { state: string }[] | undefined, bad: string, one: string, add: string): Pick<Integration, 'state' | 'detail'> {
  if (!list || list.length === 0) {
    return { state: 'off', detail: add };
  }
  const down = list.filter((x) => x.state === bad).length;
  return {
    state: down === list.length ? 'trouble' : 'on',
    detail: `${count(list.length, one)} connected${down > 0 ? `, ${String(down)} unreachable` : ''}`,
  };
}

/** A source read by flag: its own status says whether it is set up. */
function read(r: (Read & { n: number }) | undefined, one: string, flag: string): Pick<Integration, 'state' | 'detail'> {
  if (!r || r.status === 'not_configured') {
    return { state: 'off', detail: `Start the hub with ${flag}.` };
  }
  if (r.status === 'unavailable') {
    return { state: 'trouble', detail: r.error ? `Cannot be read: ${r.error}` : 'Cannot be read.' };
  }
  return { state: 'on', detail: r.status === 'connecting' ? 'Reading…' : count(r.n, one) };
}

/** A source of network hosts: on when any host was learned from it; otherwise the UI cannot tell. */
function learned(hosts: { sources: string[] }[] | undefined, source: string, flag: string): Pick<Integration, 'state' | 'detail'> {
  const n = (hosts ?? []).filter((h) => h.sources.includes(source)).length;
  return n > 0
    ? { state: 'on', detail: `${count(n, 'host')} learned from it` }
    : { state: 'host', detail: `No host learned from it. It is turned on with ${flag}.` };
}

/** Every integration, in the order the page lists them. */
export function integrations(x: IntegrationInputs): Integration[] {
  const running = (x.plugins ?? []).filter((p) => p.state === 'running').length;
  return [
    {
      id: 'kubernetes',
      name: 'Kubernetes',
      gives: 'Nodes, workloads, pods, events and logs of a cluster, and actions on them.',
      ...connected(x.clusters, 'error', 'cluster', 'Connect a cluster on the Platforms page.'),
      where: { label: 'Platforms', hash: '#/platforms' },
      docs: 'kubernetes.md',
    },
    {
      id: 'proxmox',
      name: 'Proxmox VE',
      gives: 'Hosts, VMs, LXCs and storage of a server, and starting and stopping guests.',
      ...connected(x.servers, 'unavailable', 'server', 'Connect a server on the Platforms page.'),
      where: { label: 'Platforms', hash: '#/platforms' },
      docs: 'proxmox.md',
    },
    {
      id: 'esphome',
      name: 'ESPHome',
      gives: 'Sensors, binary sensors, switches and buttons of ESPHome devices, live, through their native API.',
      ...connected(x.esphome, 'unavailable', 'device', 'Adopt a device on the Platforms page, or from On your network.'),
      where: { label: 'Platforms', hash: '#/platforms' },
      docs: 'esphome.md',
    },
    {
      id: 'talos',
      name: 'Talos API',
      gives: 'Each Talos node: its version, its system services and their health.',
      ...read(x.talos && { ...x.talos, n: x.talos.nodes.length }, 'node', '--talosconfig'),
      where: { label: 'Devices', hash: '#/' },
      docs: 'talos.md',
    },
    {
      id: 'beszel',
      name: 'Beszel',
      gives: 'The systems a Beszel hub monitors, matched to devices and hosts.',
      ...read(x.beszel && { ...x.beszel, n: x.beszel.systems.length }, 'system', '--beszel-url'),
      where: { label: 'Devices', hash: '#/' },
      docs: 'beszel.md',
    },
    {
      id: 'plugins',
      name: 'Plugins',
      gives: 'Devices, entities and commands from programs the hub runs.',
      ...(x.plugins && x.plugins.length > 0
        ? {
            state: running === 0 ? ('trouble' as const) : ('on' as const),
            detail: `${count(x.plugins.length, 'plugin')}, ${String(running)} running`,
          }
        : { state: 'off' as const, detail: 'Put a plugin in the hub’s plugins directory.' }),
      where: { label: 'Devices', hash: '#/' },
      docs: 'plugins.md',
    },
    {
      id: 'pihole',
      name: 'Pi-hole',
      gives: 'Names and addresses of hosts on the network, from its clients and leases.',
      ...learned(x.hosts, 'pihole', '--pihole-url'),
      where: { label: 'Devices', hash: '#/' },
      docs: 'pihole.md',
    },
    {
      id: 'dhcp',
      name: 'DHCP leases',
      gives: 'Hosts from a DHCP server’s lease files, on VLANs a scan cannot reach.',
      ...learned(x.hosts, 'dhcp', '--dhcp-leases'),
      where: { label: 'Devices', hash: '#/' },
      docs: 'pihole.md',
    },
    {
      id: 'netalertx',
      name: 'NetAlertX',
      gives: 'Hosts NetAlertX has seen, with their names.',
      ...learned(x.hosts, 'netalertx', '--netalertx-url'),
      where: { label: 'Devices', hash: '#/' },
      docs: 'netalertx.md',
    },
    {
      id: 'prometheus',
      name: 'Prometheus',
      gives: 'Charts of a device from your own Prometheus instead of the hub’s metrics.',
      state: 'host',
      detail: 'Turned on with --prometheus-url. A device’s charts name their source.',
      docs: 'prometheus.md',
    },
    {
      id: 'mqtt',
      name: 'MQTT broker',
      gives: 'A broker in the hub for microcontrollers and sensors, with per-client topics.',
      state: 'host',
      detail: 'Turned on with --mqtt-listen.',
      docs: 'mqtt.md',
    },
  ];
}

/** The line under the page's title. */
export function integrationSummary(list: Integration[]): string {
  const on = list.filter((i) => i.state === 'on').length;
  const bad = list.filter((i) => i.state === 'trouble').length;
  return `${String(on)} on${bad > 0 ? ` · ${String(bad)} failing` : ''}`;
}
