/**
 * Signed, chained evidence — InterMesh Action Evidence v0.1 format.
 * Records written here verify with the Python SDK and with `intermesh verify`.
 */
import { randomUUID } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalHash } from './canonical.js';
import { kidFromPem, verifyDigest, type Identity } from './identity.js';

export const SPEC_VERSION = '0.1';
export const GENESIS = '0'.repeat(64);
const REQUIRED = ['version', 'action_id', 'timestamp', 'agent_id', 'organization_id', 'action', 'risk', 'authorization', 'execution', 'prev_hash'] as const;

export type EvidenceRecord = Record<string, unknown> & {
  prev_hash: string;
  execution: Record<string, unknown>;
  evidence: { hash: string; algorithm: 'Ed25519'; signature: string; issuer: string; public_key: string; key_fingerprint: string };
};

export interface EvidenceFields {
  agentId: string;
  org: string;
  capability: string;
  risk: number;
  decision: string;
  rule: string;
  status: string;
  taskId: string;
  requester: string;
  inputHash?: string;
  responseHash?: string;
  passportId?: string;
  permitId?: string;
  timestamp?: number;
  actionId?: string;
}

const clean = (o: Record<string, unknown>) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null));

export function buildBody(f: EvidenceFields, prevHash = GENESIS): Record<string, unknown> {
  return {
    version: SPEC_VERSION,
    action_id: f.actionId ?? randomUUID(),
    timestamp: f.timestamp ?? Date.now(),
    agent_id: f.agentId,
    organization_id: f.org,
    action: clean({ method: 'TASK', target: `fsp://${f.capability}`, type: 'fsp.task', payload_hash: f.inputHash }),
    risk: { level: `R${f.risk}`, label: `R${f.risk}`, value: f.risk },
    authorization: { policy: 'franscor-agent', rule: f.rule, decision: f.decision },
    execution: clean({ status: f.status, task_id: f.taskId, requester: f.requester, response_hash: f.responseHash, passport_id: f.passportId, permit_id: f.permitId }),
    prev_hash: prevHash,
  };
}

export function signBody(body: Record<string, unknown>, identity: Identity, issuer: string): EvidenceRecord {
  const hash = canonicalHash(body);
  return {
    ...body,
    evidence: { hash, algorithm: 'Ed25519', signature: identity.signDigest(hash), issuer, public_key: identity.publicPem, key_fingerprint: identity.kid },
  } as EvidenceRecord;
}

export class EvidenceLog {
  prevHash = GENESIS;

  constructor(readonly path: string, private readonly identity: Identity, private readonly issuer: string) {
    if (existsSync(path)) {
      const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l.trim());
      const last = lines.at(-1);
      if (last) this.prevHash = (JSON.parse(last) as EvidenceRecord).evidence.hash;
    }
  }

  append(fields: EvidenceFields): EvidenceRecord {
    const record = signBody(buildBody(fields, this.prevHash), this.identity, this.issuer);
    mkdirSync(dirname(this.path), { recursive: true });
    appendFileSync(this.path, JSON.stringify(record) + '\n', 'utf8');
    this.prevHash = record.evidence.hash;
    return record;
  }
}

export interface Report {
  valid: boolean;
  count: number;
  errors: string[];
}

export function verifyRecord(record: unknown, trustedPem?: string): Report {
  const report: Report = { valid: false, count: 1, errors: [] };
  const r = record as Partial<EvidenceRecord> | null;
  if (!r || typeof r !== 'object' || typeof r.evidence !== 'object' || r.evidence === null) {
    report.errors.push('not an evidence record');
    return report;
  }
  const missing = REQUIRED.filter((f) => !(f in r));
  if (missing.length) {
    report.errors.push(`missing fields: ${missing.join(', ')}`);
    return report;
  }
  const body = Object.fromEntries(REQUIRED.map((f) => [f, (r as Record<string, unknown>)[f]]));
  const hash = canonicalHash(body);
  if (hash !== r.evidence.hash) {
    report.errors.push('content does not match its hash (modified)');
    return report;
  }
  const pem = trustedPem ?? r.evidence.public_key;
  if (!pem) {
    report.errors.push('no public key');
    return report;
  }
  if (trustedPem && r.evidence.key_fingerprint !== kidFromPem(trustedPem)) {
    report.errors.push('signed by a different key than the trusted one');
    return report;
  }
  if (!verifyDigest(pem, hash, String(r.evidence.signature ?? ''))) {
    report.errors.push('bad signature');
    return report;
  }
  report.valid = true;
  return report;
}

export function verifyChain(records: unknown[], trustedPem?: string): Report {
  const report: Report = { valid: true, count: records.length, errors: [] };
  let previous = GENESIS;
  records.forEach((record, i) => {
    const single = verifyRecord(record, trustedPem);
    if (!single.valid) {
      report.valid = false;
      report.errors.push(...single.errors.map((e) => `#${i}: ${e}`));
      return;
    }
    const r = record as EvidenceRecord;
    if (r.prev_hash !== previous) {
      report.valid = false;
      report.errors.push(`#${i}: broken chain (record removed or inserted)`);
    }
    previous = r.evidence.hash;
  });
  return report;
}

export function readLog(path: string): EvidenceRecord[] {
  return readFileSync(path, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l) as EvidenceRecord);
}
