// The short explanations behind the "?" beside a page's title. A tip says what
// the page's nouns mean, once, for whoever asks; the page itself stays free of
// standing help text. Kept apart from the components so node --test can check
// them (web/test/tips.test.mjs).

export type TipId =
  | "devices"
  | "network"
  | "platforms"
  | "automations"
  | "runbooks"
  | "panels"
  | "approvals"
  | "audit"
  | "policy"
  | "cluster"
  | "devicehub"
  | "tokens"
  | "capabilities"
  | "deviceplugins"
  | "upgrade"
  | "ai"
  | "aidraft"
  | "airecord";

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
    about: "devices",
    lines: [
      "A device is a machine Hearth knows. Most run the Hearth agent, which dials out to the hub; nothing listens on the device.",
      "What the hub may do there (logs, containers, a terminal) is switched on and off in the Capabilities card of its page, and its agent applies it at once.",
      "Scan my network lists the other hosts on your LAN: Add device puts an agent on one, Adopt keeps a printer or TV as a network device, seen but not controlled.",
    ],
    docs: "getting-started.md",
  },
  network: {
    about: "the network map",
    lines: [
      "A neighbour is someone a device sees on its own network. A connection is an established TCP connection, drawn from the client to the server and marked with the server’s port, or its service (ssh, https) when the hub knows the port. Neighbours are IPv4 (ARP) and IPv6 (NDP).",
      "Only devices with Neighbors turned on in their Capabilities report them (Linux).",
    ],
    docs: "net-edges.md",
  },
  platforms: {
    about: "platforms",
    lines: [
      "A platform is something Hearth reads through its own API: a Kubernetes cluster, a Proxmox server, an ESPHome device, an OpenWrt router, an OPNsense firewall or a UniFi controller.",
      "Nothing is installed there, and Hearth changes something only when you ask it to.",
      "An ESPHome device is read-only unless you allow calls. OpenWrt, OPNsense and UniFi clients name the hosts discovery finds.",
    ],
    docs: "kubernetes.md",
  },
  automations: {
    about: "automations",
    lines: [
      "An automation is a trigger, conditions and actions in one YAML file: when this happens and that holds, do these.",
      "Every action goes through policy. By default a dangerous action of an automation is denied.",
      "Run on the device: a check from one device and a restart there keep working while the hub is down.",
    ],
    docs: "automations.md",
  },
  runbooks: {
    about: "runbooks",
    lines: [
      "A runbook is a procedure in steps: actions, checks, prompts that wait for you, and waits.",
      "Plan shows each step and what policy would decide on it now, and runs nothing. Start run runs it; a step that fails can be retried, passed over or rolled back.",
    ],
    docs: "runbooks.md",
  },
  panels: {
    about: "panels",
    lines: [
      "A panel is a page for guests and wall screens: a few devices and the restarts a guest may take on them.",
      "It opens by a share link with no login. Deleting the panel or the link closes it at once.",
    ],
    docs: "panels.md",
  },
  approvals: {
    about: "approvals",
    lines: [
      "When policy answers confirm, the action is held here until someone approves or denies it, or it expires.",
      "Who asked does not matter: the web UI, the CLI, an automation or an MCP client all wait the same way.",
    ],
    docs: "guardrails.md",
  },
  audit: {
    about: "the audit log",
    lines: [
      "Every action is written here with who asked for it and what policy decided.",
    ],
    docs: "security.md",
  },
  policy: {
    about: "policy",
    lines: [
      "Every action has a class: read, safe or dangerous. Policy answers allow, confirm (hold for approval) or deny, per class and per kind of actor.",
      "It is checked for every action, whoever asks.",
    ],
    docs: "guardrails.md",
  },
  cluster: {
    about: "cluster roles",
    lines: [
      "Every hub is a member of a cluster with no leader. A storage member holds a replica of a share of the rows; a master serves the UI, the API and the agents and holds the hub CA key.",
      'A Linux device added with "may become a hub" ticked becomes one: a master up to 3, then storage only up to 5. Promote and demote by hand.',
      'Started on a laptop? Add two such devices, then stop it once its "safe to stop" line is green.',
    ],
    docs: "cluster.md",
  },
  devicehub: {
    about: "this device as a hub",
    lines: [
      "A device can run a hub next to its agent: it keeps a copy of the data and, as a master, serves this UI, so the cluster carries on when another hub stops.",
      "Make this device a hub gives a command to run on it; a Mac becomes a hub only this way. Make agent-only removes it from the cluster and gives the command that stops its hub service.",
    ],
    docs: "cluster.md",
  },
  tokens: {
    about: "enrollment tokens",
    lines: [
      "Add device makes a single-use enrollment token, inside the install command. It is listed here until a device enrolls with it or it expires.",
      "Revoke one you handed out by mistake: no device can enroll with it. A hub-eligible token may make its device a hub, so revoking it asks for your password again, as creating it did.",
    ],
    docs: "security.md",
  },
  capabilities: {
    about: "capabilities",
    lines: [
      "What the hub may do on this device. Its agent applies a change at once and checks every request against it itself.",
      "Turning on a terminal, programs, restarts or container control asks for your password again. What a flag on the device grants shows as set there; the hub cannot take it away.",
      "A device installed with --local-ceiling ignores what is set here.",
    ],
    docs: "security.md",
  },
  deviceplugins: {
    about: "device plugins",
    lines: [
      "Programs you upload here run on a device, as its agent's user, and speak the same JSON lines as the hub's exec plugins. A device gets one when you grant it under Capabilities.",
      "Uploading asks for your password again. A command's class decides what policy asks before it runs.",
    ],
    docs: "plugins.md",
  },
  upgrade: {
    about: "upgrading the agent",
    lines: [
      "Upgrade agent (or hearth device upgrade) brings the agent to the hub's version: it downloads the release (from GitHub, or its --release-mirror), checks its signed checksums, swaps its binary and restarts. It asks for the admin password again.",
      "If the new version reaches no hub, the agent puts the old one back and this page says so.",
      "An agent older than remote upgrades needs the installer run on the device once; one in a Kubernetes pod, a new image",
    ],
    docs: "getting-started.md",
  },
  ai: {
    about: "Explain with AI",
    lines: [
      "Explain sends what the hub knows about a device (its facts, a metrics summary, recent audit entries and any log tail you add) to the model set up in Settings, AI. Passwords, tokens and keys are redacted first; What was sent shows every byte.",
      "The model never runs anything: a fix it suggests is yours to take, through the usual controls and policy. AI is off until an admin sets it up; a local Ollama keeps it all in the lab.",
    ],
    docs: "ai.md",
  },
  aidraft: {
    about: "drafting automations with AI",
    lines: [
      "Describe what you want and the model set up in Settings, AI writes the file, using the names of your devices, channels, clusters and plugins (redacted). The hub checks it, and asks once more if it is invalid.",
      "Nothing is saved or turned on: the draft opens here, unsaved, with its dry run. Review it, then Save, where policy decides as for any edit.",
    ],
    docs: "ai.md",
  },
  airecord: {
    about: "recording a session for a runbook",
    lines: [
      "A terminal opened with Record for a runbook keeps what the screen shows, never what you type at a hidden password prompt, in the hub's memory only, for an hour after it ends.",
      "Make a runbook sends it, redacted, to the model set up in Settings, AI, and deletes it. The draft opens unsaved in the runbook editor; saving is as for any edit.",
    ],
    docs: "ai.md",
  },
};
