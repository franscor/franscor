/**
 * Receiver-side authorization — the security boundary. Default deny:
 * own org only, R4 and above require a human approval handler.
 */
import type { Capability } from './capabilities.js';

export type Decision = 'allow' | 'block' | 'approval';

export interface CardLike {
  agent_id?: string;
  org?: string;
}

export class AgentPolicy {
  acceptOrgs: string[];
  acceptAgents: string[];

  constructor(readonly org: string, acceptOrgs: string[] = [], acceptAgents: string[] = [], public approvalThreshold = 4) {
    this.acceptOrgs = acceptOrgs.length ? [...acceptOrgs] : [org];
    this.acceptAgents = [...acceptAgents];
  }

  accepts(sender: CardLike): boolean {
    return this.acceptOrgs.includes('*') || this.acceptOrgs.includes(sender.org ?? '') || this.acceptAgents.includes(sender.agent_id ?? '');
  }

  decide(sender: CardLike, cap: Capability | undefined): [Decision, string] {
    if (!cap) return ['block', 'unknown-capability'];
    if (!this.accepts(sender)) return ['block', 'sender-not-accepted'];
    if (cap.risk >= this.approvalThreshold) return ['approval', `risk-R${cap.risk}-requires-approval`];
    return ['allow', 'accepted'];
  }

  cardAccepts(): { orgs: string[]; agents: string[] } {
    return { orgs: [...this.acceptOrgs], agents: [...this.acceptAgents] };
  }
}
