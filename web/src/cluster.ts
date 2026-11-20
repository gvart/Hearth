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
