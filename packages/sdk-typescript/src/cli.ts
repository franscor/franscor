#!/usr/bin/env node
/** `franscor` CLI (TypeScript): detect, identity, verify, passport, permit, audit. The hub ships with the Python package. */
import { readFileSync } from 'node:fs';
import { detect } from './detect.js';
import { readLog, verifyChain } from './evidence.js';
import type { FSPError } from './errors.js';
import { agentIdFromPem, Identity } from './identity.js';
import { verifyCrl, verifyPassport, type PassportCrl } from './passport.js';
import { verifyPermit } from './permit.js';
import { verifyBundle } from './blackbox.js';

const [cmd, ...args] = process.argv.slice(2);

switch (cmd) {
  case 'detect':
    console.log(JSON.stringify(detect(), null, 2));
    break;
  case 'identity': {
    if (!args[0]) throw new Error('usage: franscor identity <name>');
    const id = Identity.loadOrCreate(args[0]);
    console.log(JSON.stringify({ agentId: id.agentId, kid: id.kid, path: Identity.pathFor(args[0]), publicKey: id.publicPem }, null, 2));
    break;
  }
  case 'verify': {
    if (!args[0]) throw new Error('usage: franscor verify <evidence.jsonl> [--key public.pem]');
    const k = args.indexOf('--key');
    const key = k >= 0 && args[k + 1] ? readFileSync(args[k + 1]!, 'utf8') : undefined;
    const report = verifyChain(readLog(args[0]), key);
    console.log(JSON.stringify(report, null, 2));
    if (!key) console.error('note: no --key given; records are checked against the key they carry (integrity, not issuer)');
    process.exitCode = report.valid ? 0 : 1;
    break;
  }
  case 'passport': {
    // Issuing and revoking are hub operations (Python hub); agents show and verify.
    const [sub, file] = args;
    const flag = (name: string) => {
      const i = args.indexOf(name);
      return i >= 0 ? args[i + 1] : undefined;
    };
    if (!file || (sub !== 'show' && sub !== 'verify')) {
      console.error('usage: franscor passport show <file> | passport verify <file> [--hub-key pem] [--crl file]');
      process.exitCode = 2;
      break;
    }
    const doc = JSON.parse(readFileSync(file, 'utf8'));
    if (sub === 'show') {
      const iso = (ms: number) => new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
      if (doc.type === 'passport-crl') {
        console.log(`CRL of hub ${doc.hub_id}  serial ${doc.serial}  issued ${iso(doc.issued_at)}`);
        for (const e of doc.revoked ?? []) console.log(`  ${e.passport_id}  agent ${e.agent_id || '-'}  ${iso(e.revoked_at)}  ${e.ban ? 'ban' : 'passport only'}  ${e.reason ?? ''}`);
      } else {
        for (const [label, key] of [['passport', 'passport_id'], ['agent', 'agent_id'], ['org', 'org'], ['issued by hub', 'hub_id']]) console.log(`${label!.padStart(14)}: ${doc[key!]}`);
        console.log(`${'capabilities'.padStart(14)}: ${(doc.capabilities ?? []).join(', ') || '-'}`);
        console.log(`${'valid from'.padStart(14)}: ${iso(doc.issued_at)}`);
        console.log(`${'valid until'.padStart(14)}: ${iso(doc.expires_at)}`);
      }
      break;
    }
    const hubKeyFile = flag('--hub-key');
    const crlFile = flag('--crl');
    let trustedHubs: Record<string, string> | undefined;
    let crls: Record<string, PassportCrl> | undefined;
    try {
      if (hubKeyFile) {
        const pem = readFileSync(hubKeyFile, 'utf8');
        trustedHubs = { [agentIdFromPem(pem)]: pem };
        if (crlFile) {
          const crl = verifyCrl(JSON.parse(readFileSync(crlFile, 'utf8')), pem);
          crls = { [crl.hub_id]: crl };
        }
      } else {
        console.error('note: no --hub-key; checking integrity against the key the passport carries, not who issued it');
      }
      verifyPassport(doc, { trustedHubs, crls });
      console.log(JSON.stringify({ valid: true, passport_id: doc.passport_id, agent_id: doc.agent_id, expires_at: doc.expires_at, revocation_checked: !!crls }));
    } catch (err) {
      console.log(JSON.stringify({ valid: false, code: (err as FSPError).code, error: (err as Error).message }));
      process.exitCode = 1;
    }
    break;
  }
  case 'permit': {
    // Permits are issued by the receiving hub (Python, from its peering file); agents show and verify.
    const [sub, file] = args;
    const flag = (name: string) => {
      const i = args.indexOf(name);
      return i >= 0 ? args[i + 1] : undefined;
    };
    if (!file || (sub !== 'show' && sub !== 'verify')) {
      console.error('usage: franscor permit show <file> | permit verify <file> [--hub-key pem] [--capability name]');
      process.exitCode = 2;
      break;
    }
    const doc = JSON.parse(readFileSync(file, 'utf8'));
    if (sub === 'show') {
      const iso = (ms: number) => new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
      for (const [label, key] of [['permit', 'permit_id'], ['agent', 'agent_id'], ['org', 'org'], ['passport', 'passport_id'],
        ['partner hub', 'peer_hub_id'], ['issued by hub', 'hub_id']]) console.log(`${label!.padStart(14)}: ${doc[key!]}`);
      console.log(`${'capabilities'.padStart(14)}: ${(doc.capabilities ?? []).join(', ') || '-'}`);
      console.log(`${'scopes'.padStart(14)}: ${(doc.scopes ?? []).join(', ') || '-'}`);
      console.log(`${'limits'.padStart(14)}: ${doc.rate_per_min}/min, depth <= ${doc.max_depth}${doc.messages ? ', messages' : ''}`);
      console.log(`${'valid from'.padStart(14)}: ${iso(doc.issued_at)}`);
      console.log(`${'valid until'.padStart(14)}: ${iso(doc.expires_at)}`);
      break;
    }
    const hubKeyFile = flag('--hub-key');
    try {
      let trustedHubs: Record<string, string> | undefined;
      if (hubKeyFile) {
        const pem = readFileSync(hubKeyFile, 'utf8');
        trustedHubs = { [agentIdFromPem(pem)]: pem };
      } else {
        console.error('note: no --hub-key; checking integrity against the key the permit carries, not who issued it');
      }
      verifyPermit(doc, { trustedHubs, capability: flag('--capability') });
      console.log(JSON.stringify({ valid: true, permit_id: doc.permit_id, agent_id: doc.agent_id, expires_at: doc.expires_at }));
    } catch (err) {
      console.log(JSON.stringify({ valid: false, code: (err as FSPError).code, error: (err as Error).message }));
      process.exitCode = 1;
    }
    break;
  }
  case 'audit': {
    // Hubs keep and export the black box (Python); anyone verifies a bundle.
    const [sub, file] = args;
    const flag = (name: string) => {
      const i = args.indexOf(name);
      return i >= 0 ? args[i + 1] : undefined;
    };
    if (!file || (sub !== 'show' && sub !== 'verify')) {
      console.error('usage: franscor audit show <bundle> | audit verify <bundle> [--hub-key pem] [--witness-key pem ...] [--previous bundle|checkpoint]');
      process.exitCode = 2;
      break;
    }
    const bundle = JSON.parse(readFileSync(file, 'utf8'));
    if (sub === 'show') {
      const iso = (ms: number) => new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
      const cp = bundle.checkpoint;
      console.log(`bundle of hub ${bundle.hub_id}: checkpoint size ${cp.tree_size} root ${cp.root} ${iso(cp.ts)}`);
      console.log(`cosignatures: ${(bundle.cosignatures ?? []).map((c: { witness_id: string }) => c.witness_id).join(', ') || '-'}`);
      for (const e of (bundle.entries ?? []).slice(-20)) {
        const d = JSON.parse(e.leaf);
        console.log(`  #${String(d.index).padEnd(6)} ${iso(d.ts)}  ${String(d.decision).padEnd(11)} ${String(d.route).padEnd(8)} ${String(d.frame).padEnd(12)} ${d.from ?? '-'} -> ${d.to ?? '-'}`);
      }
      break;
    }
    const hubKeyFile = flag('--hub-key');
    const witnessKeys: Record<string, string> = {};
    args.forEach((a, i) => {
      if (a === '--witness-key' && args[i + 1]) {
        const pem = readFileSync(args[i + 1]!, 'utf8');
        witnessKeys[agentIdFromPem(pem)] = pem;
      }
    });
    const prevFile = flag('--previous');
    let previous: unknown;
    if (prevFile) {
      const doc = JSON.parse(readFileSync(prevFile, 'utf8'));
      previous = doc.type === 'audit-bundle' ? doc.checkpoint : doc;
    }
    if (!hubKeyFile) console.error('note: no --hub-key; checking integrity against the key the bundle carries, not who signed it');
    const report = verifyBundle(bundle, {
      hubPublicKey: hubKeyFile ? readFileSync(hubKeyFile, 'utf8') : undefined,
      witnessKeys: Object.keys(witnessKeys).length ? witnessKeys : undefined,
      previous,
    });
    console.log(JSON.stringify(report));
    process.exitCode = report.valid ? 0 : 1;
    break;
  }
  case 'hub':
    console.error('The reference hub ships with the Python package: pip install franscor && franscor hub');
    process.exitCode = 2;
    break;
  default:
    console.log('usage: franscor <detect | identity <name> | verify <file> [--key pem] | passport show|verify <file> | permit show|verify <file> | audit show|verify <bundle>>');
    process.exitCode = cmd ? 2 : 0;
}
