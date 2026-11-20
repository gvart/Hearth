// What the editor says and allows around a save. No React here: test/ runs
// this under Node.

export interface SaveAnswer {
  file: string;
  /** The address of the hub that holds the file now. */
  hub: string;
  /** This hub is one of several. */
  cluster: boolean;
  /** This hub runs automations now. */
  leader: boolean;
  /** The automation is in the cluster's store, on every hub. */
  stored?: boolean;
  /** What to know about a save that worked. */
  warning?: string;
}

export interface ApprovalDetailParts {
  planText: string;
  /** An approval link does not carry the plan: it is shown to those signed in. */
  planWithheld?: boolean;
  rest: Record<string, unknown>;
}

/** Splits an approval's plan, which is read as text, from its other details. */
export function approvalDetail(detail: Record<string, unknown>): ApprovalDetailParts {
  const { plan_withheld: withheld, ...others } = detail;
  const note = withheld === true ? { planWithheld: true } : {};
  const { plan, ...rest } = others;
  return typeof plan === 'string' ? { planText: plan, ...note, rest } : { planText: '', ...note, rest: others };
}

/** A pending save is of the file as it was sent: nothing may change under it. */
export function mayEdit(savePending: boolean): boolean {
  return !savePending;
}

/** Says where the file is, and what still has to happen for it to run. */
export function savedNotice({ file, hub, cluster, leader, stored, warning }: SaveAnswer): string {
  const where = `Saved to ${file} on ${hub} only.`;
  const notice = !cluster
    ? `Saved to ${file}. The hub loads it within seconds.`
    : stored
      ? `Saved to ${file}. Every hub has it within seconds, and the cluster's leader runs it.`
      : leader
      ? `${where} This hub leads the cluster and runs it now. Copy the file to the other hubs, or it stops running when another hub takes over.`
      : `${where} This hub is a follower and only the leader runs automations: copy the file to the leader and the other hubs.`;
  return warning ? `${notice} ${warning}` : notice;
}
