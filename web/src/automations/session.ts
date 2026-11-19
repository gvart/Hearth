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
}

/** Splits an approval's plan, which is read as text, from its other details. */
export function approvalDetail(detail: Record<string, unknown>): { planText: string; rest: Record<string, unknown> } {
  const { plan, ...rest } = detail;
  return typeof plan === 'string' ? { planText: plan, rest } : { planText: '', rest: detail };
}

/** A pending save is of the file as it was sent: nothing may change under it. */
export function mayEdit(savePending: boolean): boolean {
  return !savePending;
}

/** Says where the file is, and what still has to happen for it to run. */
export function savedNotice({ file, hub, cluster, leader }: SaveAnswer): string {
  if (!cluster) {
    return `Saved to ${file}. The hub loads it within seconds.`;
  }
  const where = `Saved to ${file} on ${hub} only.`;
  return leader
    ? `${where} This hub leads the cluster and runs it now. Copy the file to the other hubs, or it stops running when another hub takes over.`
    : `${where} This hub is a follower and only the leader runs automations: copy the file to the leader and the other hubs.`;
}
