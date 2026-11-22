// The short explanations behind the "?" beside a page's title. A tip says what
// the page's nouns mean, once, for whoever asks; the page itself stays free of
// standing help text. Kept apart from the components so node --test can check
// them (web/test/tips.test.mjs).

export type TipId =
  | 'devices'
  | 'network'
  | 'platforms'
  | 'automations'
  | 'runbooks'
  | 'panels'
  | 'approvals'
  | 'audit'
  | 'policy'
  | 'cluster';

export interface TipText {
  /** What the "?" is about, for a screen reader: "About runbooks". */
  about: string;
  /** Two or three sentences. */
  lines: string[];
  /** The page of the docs that says the rest, under docs/. */
  docs?: string;
}

export const tips: Record<TipId, TipText> = {
  devices: {
    about: 'devices',
    lines: [
      'A device is a machine Hearth knows. Most run the Hearth agent, which dials out to the hub; nothing listens on the device.',
      'What the hub may do there is set where the agent is started, with its --allow flags. The hub can never grant more.',
      'Scan my network lists the other hosts on your LAN: Add device puts an agent on one, Adopt keeps a printer or TV as a network device, seen but not controlled.',
    ],
    docs: 'getting-started.md',
  },
  network: {
    about: 'the network map',
    lines: [
      'A neighbour is someone a device sees on its own network. A connection is an established TCP connection, drawn from the client to the server and marked with the server’s port.',
      'Only agents started with --allow-net-edges report them.',
    ],
    docs: 'net-edges.md',
  },
  platforms: {
    about: 'platforms',
    lines: [
      'A platform is a cluster or server Hearth reads through its own API: a Kubernetes cluster or a Proxmox server.',
      'Nothing is installed there, and Hearth changes something only when you ask it to.',
    ],
    docs: 'kubernetes.md',
  },
  automations: {
    about: 'automations',
    lines: [
      'An automation is a trigger, conditions and actions in one YAML file: when this happens and that holds, do these.',
      'Every action goes through policy. By default a dangerous action of an automation is denied.',
    ],
    docs: 'automations.md',
  },
  runbooks: {
    about: 'runbooks',
    lines: [
      'A runbook is a procedure in steps: actions, checks, prompts that wait for you, and waits.',
      'Plan shows each step and what policy would decide on it now, and runs nothing. Start run runs it; a step that fails can be retried, passed over or rolled back.',
    ],
    docs: 'runbooks.md',
  },
  panels: {
    about: 'panels',
    lines: [
      'A panel is a page for guests and wall screens: a few devices and the restarts a guest may take on them.',
      'It opens by a share link with no login. Deleting the panel or the link closes it at once.',
    ],
    docs: 'panels.md',
  },
  approvals: {
    about: 'approvals',
    lines: [
      'When policy answers confirm, the action is held here until someone approves or denies it, or it expires.',
      'Who asked does not matter: the web UI, the CLI, an automation or an MCP client all wait the same way.',
    ],
    docs: 'guardrails.md',
  },
  audit: {
    about: 'the audit log',
    lines: ['Every action is written here with who asked for it and what policy decided.'],
    docs: 'security.md',
  },
  policy: {
    about: 'policy',
    lines: [
      'Every action has a class: read, safe or dangerous. Policy answers allow, confirm (hold for approval) or deny, per class and per kind of actor.',
      'It is checked for every action, whoever asks.',
    ],
    docs: 'guardrails.md',
  },
  cluster: {
    about: 'cluster roles',
    lines: [
      'Every hub is a member of a cluster with no leader. A storage member holds a replica of a share of the rows; a master serves the UI, the API and the agents and holds the hub CA key.',
      'Promote gives a member a role, demote takes it away. The hub refuses to take away the last master or the last storage member.',
      'Before you stop a hub, check its "safe to stop" line: green means every row it holds has a caught-up copy on another hub, and another master is live.',
    ],
    docs: 'cluster.md',
  },
};
