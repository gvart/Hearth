// The members of an AP cluster and what an admin can do with each: kept
// apart from the components so node --test can check it
// (web/test/cluster.test.mjs). See docs/cluster.md.

export type ClusterRole = 'storage' | 'master';

export interface ClusterMember {
  id: string;
  address: string;
  /** Its roles now: storage, master (and node, for an agent host). */
  roles: string[];
  /** Its --allow-roles, the ceiling of its roles. */
  allowed_roles: string[];
  /** alive, suspect, dead or left. */
  state: string;
  /** Promoted to storage, still copying its rows. */
  syncing?: boolean;
  /** Being demoted from storage, handing its rows off; progress in percent. */
  draining?: boolean;
  progress?: number;
}

/** GET /api/v1/cluster/members: this hub's view of its AP cluster. */
export interface ClusterStatus {
  node_id: string;
  members?: ClusterMember[];
  storage_members?: number;
  replicas?: number;
  highly_available?: boolean;
}

export type ClusterOp = 'promote' | 'demote' | 'remove';

export interface ClusterAction {
  op: ClusterOp;
  role?: ClusterRole;
  label: string;
}

const roles: ClusterRole[] = ['storage', 'master'];

/**
 * The actions offered on member m: promote to each role it allows and lacks,
 * demote from each it holds, and remove, except for the hub showing the page.
 * The hub refuses what it must (the last master, the last storage member, a
 * member's last role); the page does not second-guess it.
 */
export function memberActions(m: ClusterMember, self: string): ClusterAction[] {
  const out: ClusterAction[] = [];
  for (const role of roles) {
    if (m.roles.includes(role)) {
      out.push({ op: 'demote', role, label: `Demote from ${role}` });
    } else if (m.allowed_roles.includes(role)) {
      out.push({ op: 'promote', role, label: `Promote to ${role}` });
    }
  }
  if (m.id !== self) {
    out.push({ op: 'remove', label: 'Remove' });
  }
  return out;
}

/** One of the two roles on a member's card: held, allowed and not taken (open), or not allowed (off). */
export interface RoleSlot {
  role: ClusterRole;
  state: 'held' | 'open' | 'off';
  /** What holding it means here, or why it is not held. */
  text: string;
  /** Demote from a role it holds, promote to one it allows. The hub refuses what it must. */
  action?: ClusterAction;
}

/** A member's two role slots, master first. */
export function roleSlots(m: ClusterMember): RoleSlot[] {
  return (['master', 'storage'] as const).map((role) => {
    if (m.roles.includes(role)) {
      const text =
        role === 'master'
          ? 'Serves the UI, the API and agents. Holds the CA key.'
          : m.syncing
            ? 'Copying its share of the store.'
            : m.draining
              ? 'Handing its rows to the other members.'
              : 'Keeps a share of the store.';
      return { role, state: 'held', text, action: { op: 'demote', role, label: `Demote from ${role}` } };
    }
    if (m.allowed_roles.includes(role)) {
      return {
        role,
        state: 'open',
        text: 'Allowed on this host, not taken.',
        action: { op: 'promote', role, label: `Promote to ${role}` },
      };
    }
    return { role, state: 'off', text: 'Not allowed by this host (--allow-roles).' };
  });
}

/** How many members serve the UI, the API and agents. */
export function masterCount(members: ClusterMember[]): number {
  return members.filter((m) => m.roles.includes('master')).length;
}

/** What an action does, for its confirm dialog. */
export function actionEffect(a: ClusterAction, member: string): string {
  switch (a.op) {
    case 'promote':
      return a.role === 'storage'
        ? `${member} joins the storage ring and copies its share of the rows from the other members. It shows "syncing" and serves no reads until it holds them all.`
        : `${member} fetches the CA key from this hub over the pinned TLS channel and starts serving the API, the UI and agents.`;
    case 'demote':
      return a.role === 'storage'
        ? `${member} hands its rows off to the other storage members and keeps the role ("draining") until every row has its copies there. Then it leaves the ring.`
        : `${member} spends its unused enrollment and join tokens, expires its pending approvals and deletes its CA key. Its agents move to the other masters.`;
    case 'remove':
      return `${member}'s hub certificates are revoked and every member forgets it; the others re-replicate the rows it held. To come back, it joins again with a new join token.`;
  }
}

/** The member's state as one line: alive, syncing, draining 40%. */
export function memberState(m: ClusterMember): { label: string; tone: 'ok' | 'warn' | 'bad' | 'muted' } {
  if (m.state === 'alive' || m.state === 'suspect') {
    if (m.draining) {
      return { label: `draining ${String(m.progress ?? 0)}%`, tone: 'warn' };
    }
    if (m.syncing) {
      return { label: 'syncing', tone: 'warn' };
    }
    return m.state === 'alive' ? { label: 'alive', tone: 'ok' } : { label: 'suspect', tone: 'warn' };
  }
  return m.state === 'left' ? { label: 'left', tone: 'muted' } : { label: m.state, tone: 'bad' };
}

/** A member's side of a hub CA rotation (GET /api/v1/cluster/ca). Fingerprints are short. */
export interface HubCA {
  id: string;
  master: boolean;
  serving?: string;
  next?: string;
  has_next_key?: boolean;
  has_next_cert?: boolean;
  cut_over?: boolean;
  /** Why its side is unknown: its state (dead, left, suspect) or that it says nothing yet. */
  error?: string;
}

/** A hub CA rotation. */
export interface CARotation {
  new_ca_fp: string;
  old_ca_fp: string;
  /** started, cutover, finished or aborted. */
  stage: string;
  active: boolean;
  started_at: string;
  updated_at: string;
  /** The master that drives it. */
  owner: string;
  owner_alive: boolean;
  owner_url?: string;
}

/** GET /api/v1/cluster/ca: the latest rotation and every member's side of it. */
export interface ClusterCA {
  node_id: string;
  rotation?: CARotation;
  hubs: HubCA[];
  /** Agents still holding only an old-CA certificate: a finish refuses while there are any. */
  old_devices?: string[];
}

export type CAStep = 'rotate' | 'finish' | 'abort';

/** The gossip's form of a CA fingerprint. */
export function shortFP(fp: string): string {
  return fp.slice(0, 16);
}

/** Where member h is in the rotation's current stage: ready, or what it still lacks. */
export function hubProgress(h: HubCA, rot: CARotation): { ready: boolean; label: string; tone: 'ok' | 'warn' | 'bad' } {
  if (h.error) {
    return { ready: false, label: h.error.startsWith('it says nothing') ? 'no answer yet' : h.error, tone: 'bad' };
  }
  if (rot.stage === 'cutover') {
    return h.cut_over ? { ready: true, label: 'cut over', tone: 'ok' } : { ready: false, label: 'cutting over', tone: 'warn' };
  }
  if (h.next !== shortFP(rot.new_ca_fp)) {
    return { ready: false, label: 'fetching the new CA', tone: 'warn' };
  }
  if (!h.has_next_cert) {
    return { ready: false, label: 'fetching its certificate', tone: 'warn' };
  }
  if (h.master && !h.has_next_key) {
    return { ready: false, label: 'fetching the key', tone: 'warn' };
  }
  return { ready: true, label: 'ready', tone: 'ok' };
}

/** The members a finish still waits for, each with what it lacks. */
export function waitingFor(st: ClusterCA): string[] {
  const rot = st.rotation;
  if (!rot?.active) {
    return [];
  }
  return st.hubs.flatMap((h) => {
    const p = hubProgress(h, rot);
    return p.ready ? [] : [`${h.id} (${p.label})`];
  });
}

/** The steps offered: a start with no rotation under way; with one, a finish, and an abort before the cutover. */
export function caSteps(st: ClusterCA | undefined): CAStep[] {
  const rot = st?.rotation;
  if (!rot?.active) {
    return ['rotate'];
  }
  return rot.stage === 'started' ? ['finish', 'abort'] : ['finish'];
}

/** What a step does, in plain words, for its confirm dialog. */
export function caStepEffect(step: CAStep): string[] {
  switch (step) {
    case 'rotate':
      return [
        'This master makes a new hub CA and owns the rotation. Every member gets a node certificate of the new CA, and every master its key, over the masters’ mutual TLS; a storage-only member never gets the key.',
        'Each agent that connects gets a certificate of the new CA and trusts both. An agent offline until the finish is cut off then, and has to enroll again.',
        'Every member must be up. Until the rotation ends, no hub can join and no member is promoted to master or demoted from it.',
      ];
    case 'finish':
      return [
        'Every member switches to the new CA, the sealed secrets are re-sealed with its key, every member drops the old CA and every master deletes its key.',
        'Agents and members still holding only an old-CA certificate are cut off. A member that is down stops the finish: bring it back and finish again, or remove it.',
        'Browsers and phones that trust the old CA must fetch the new one from /ca.crt. Enroll and join tokens made before the finish stop working.',
      ];
    case 'abort':
      return [
        'Every member drops the new CA, its key and its certificates of it, and what the new CA issued is revoked: agents it already renewed have to enroll again.',
        'Hubs can join again, and a new rotation can start.',
      ];
  }
}

/** A refusal of a rotation step from the hub, worded for the dialog. */
export function caRefusalMessage(code: string, message: string, rot: CARotation | undefined): string {
  if (code === 'rotation_owner' && rot?.owner) {
    return `Master ${rot.owner} owns this rotation and is alive: finish or abort it on its Cluster page${rot.owner_url ? ` (${rot.owner_url})` : ''}.`;
  }
  return refusalMessage(code, message);
}

/** A refusal from the hub, worded for the dialog. */
export function refusalMessage(code: string, message: string): string {
  switch (code) {
    case 'forbidden':
      return 'Denied by policy. See the policy configuration, or the Audit page.';
    case 'isolated':
      return 'This hub has reached no other member of the cluster for a while: it refuses dangerous actions until it does.';
    case 'not_allowed':
      return `The member does not allow this role (its --allow-roles): ${message}`;
  }
  return message;
}
