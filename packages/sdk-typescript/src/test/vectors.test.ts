import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalHash, canonicalJson, CanonicalError } from '../canonical.js';
import { digest, seal, verifyEnvelope, type Envelope } from '../envelope.js';
import { buildBody, signBody, verifyRecord } from '../evidence.js';
import { Identity } from '../identity.js';
import { makeRevocation, makeRotation, verifyRevocation, verifyRotation } from '../statements.js';
import { aad, cardVerified, encKeyOf, encPublicB64, openSealed, sealPayload, signCard } from '../sealing.js';
import { issuePassport, makeCrl, verifyCrl, verifyPassport } from '../passport.js';
import { issuePermit, verifyPermit } from '../permit.js';
import { leafHash, merkleRoot, verifyBundle, verifyCheckpoint, verifyConsistency, verifyCosignature, verifyInclusion } from '../blackbox.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, '..', '..', '..', '..', 'protocol', 'vectors', 'vectors.json'), 'utf8'));
const ident = Identity.fromSeed(Buffer.from(vectors.seed_hex, 'hex'));

test('identity derivation matches Python', () => {
  assert.equal(ident.agentId, vectors.identity.agent_id);
  assert.equal(ident.kid, vectors.identity.kid);
  assert.equal(ident.publicPem, vectors.identity.public_key);
});

test('canonical JSON is byte-identical', () => {
  for (const c of vectors.canonical) {
    assert.equal(canonicalJson(c.value), c.json);
    assert.equal(canonicalHash(c.value), c.sha256);
  }
  assert.throws(() => canonicalJson(Number.NaN), CanonicalError);
  for (const bad of [2 ** 53, 1e20, 1e21, Infinity, 10n]) assert.throws(() => canonicalJson(bad), CanonicalError);
});

test('envelope signature is reproduced exactly and verifies', () => {
  const v = vectors.envelope.value as Envelope;
  assert.equal(digest(v as unknown as Record<string, unknown>), vectors.envelope.digest);
  const mine = seal(ident, 'task.request', v.body as Record<string, unknown>, { to: v.to!, ts: v.ts, id: v.id });
  assert.deepEqual(mine, v);
  verifyEnvelope(v, ident.publicPem, { checkTime: false });
  const tampered = structuredClone(v);
  (tampered.body as { input: { a: number } }).input.a = 3;
  assert.throws(() => verifyEnvelope(tampered, ident.publicPem, { checkTime: false }), /FSP-1100/);
  assert.throws(() => verifyEnvelope(v, ident.publicPem), /FSP-1102/);
});

test('evidence record is reproduced exactly and verifies', () => {
  const r = vectors.evidence;
  const mine = signBody(
    buildBody({
      agentId: ident.agentId, org: 'acme', capability: 'math.add', risk: 2, decision: 'allow', rule: 'accepted',
      status: 'executed', taskId: 'task-0001', requester: 'fsp:' + '0'.repeat(32),
      inputHash: canonicalHash({ a: 2, b: 0.5 }), responseHash: canonicalHash({ sum: 2.5 }),
      timestamp: 1763290000123, actionId: '00000000-0000-4000-8000-000000000002',
    }),
    ident,
    'acme',
  );
  assert.deepEqual(mine, r);
  assert.equal(verifyRecord(r, ident.publicPem).valid, true);
});

test('rotation and revocation statements match Python and verify', () => {
  const next = Identity.fromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32)));
  assert.deepEqual(makeRotation(ident, next, 1763290000456), vectors.rotation);
  assert.deepEqual(makeRevocation(ident, 'key compromised', 1763290000789), vectors.revocation);
  verifyRotation(vectors.rotation);
  verifyRevocation(vectors.revocation);
  const bad = structuredClone(vectors.rotation);
  bad.sigs.new = bad.sigs.old;
  assert.throws(() => verifyRotation(bad), /FSP-1100/);
});

test('encryption key, sealed payload and signed card match Python', () => {
  assert.equal(encPublicB64(ident), vectors.enc_key);
  const v = vectors.sealed;
  const ad = aad(v.aad.type, v.aad.from, v.aad.to, v.aad.ref);
  const mine = sealPayload(v.data, vectors.enc_key, ad, { ephemeralSeed: Buffer.from(v.ephemeral_seed_hex, 'hex'), nonce: Buffer.from(v.nonce_hex, 'hex') });
  assert.deepEqual(mine, v.value);
  assert.deepEqual(openSealed(v.value, ident, ad), v.data);
  assert.throws(() => openSealed(v.value, ident, aad(v.aad.type, v.aad.from, v.aad.to, 'task-0002')), /FSP-1100/);
  const { card_sig: _sig, ...unsigned } = vectors.card;
  assert.deepEqual(signCard(unsigned, ident), vectors.card);
  assert.equal(cardVerified(vectors.card), true);
  assert.equal(encKeyOf({ ...vectors.card, enc_key: encPublicB64(Identity.generate()) }), undefined);
});

test('passport and CRL match Python byte for byte; checks agree', () => {
  const hub = Identity.fromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32)));
  const p = vectors.passport;
  const mine = issuePassport(hub, {
    agentId: ident.agentId, org: 'acme', agentPublicKey: ident.publicPem, capabilities: ['text.upper', 'math.add'],
    ttlMs: 3_600_000, now: 1763290000000, passportId: 'pp_' + 'ab'.repeat(16),
  });
  assert.deepEqual(mine, p);
  const trustedHubs = { [hub.agentId]: hub.publicPem };
  assert.equal(verifyPassport(p, { trustedHubs, now: 1763290001000 }).agent_id, ident.agentId);
  const crl = verifyCrl(vectors.passport_crl, hub.publicPem);
  assert.deepEqual(makeCrl(hub, crl.revoked, 2, 1763290200000), vectors.passport_crl);
  const code = (fn: () => unknown) => {
    try {
      fn();
      return 'ok';
    } catch (err) {
      return (err as { code?: string }).code;
    }
  };
  assert.equal(code(() => verifyPassport(p, { trustedHubs, crls: { [hub.agentId]: crl }, now: 1763290001000 })), 'FSP-1108');
  assert.equal(code(() => verifyPassport(p, { trustedHubs, now: 1763293600000 })), 'FSP-1107');
  assert.equal(code(() => verifyPassport({ ...p, capabilities: ['admin'] }, { trustedHubs, now: 1763290001000 })), 'FSP-1106');
  assert.equal(code(() => verifyPassport(p, { trustedHubs: { [ident.agentId]: ident.publicPem }, now: 1763290001000 })), 'FSP-1106');
  assert.equal(code(() => verifyPassport(p, { trustedHubs, agentId: hub.agentId, now: 1763290001000 })), 'FSP-1106');
  assert.equal(code(() => verifyCrl({ ...vectors.passport_crl, serial: 9 }, hub.publicPem)), 'FSP-1106');
});

test('permit matches Python byte for byte; checks agree', () => {
  const receiving = Identity.fromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 128)));
  const p = vectors.permit;
  const mine = issuePermit(receiving, vectors.passport, {
    capabilities: ['invoice.total', 'fx.*'], scopes: ['invoices:read'], messages: false, ratePerMin: 60, maxDepth: 1,
    ttlMs: 1_800_000, now: 1763290000500, permitId: 'pm_' + 'cd'.repeat(16),
  });
  assert.deepEqual(mine, p);
  const trustedHubs = { [receiving.agentId]: receiving.publicPem };
  const now = 1763290001000;
  const code = (fn: () => unknown) => {
    try {
      fn();
      return 'ok';
    } catch (err) {
      return (err as { code?: string }).code;
    }
  };
  const ok = { trustedHubs, now, agentId: vectors.passport.agent_id, passport: vectors.passport };
  assert.equal(code(() => verifyPermit(p, { ...ok, capability: 'fx.rate', scopes: ['invoices:read'], depth: 1 })), 'ok');
  assert.equal(code(() => verifyPermit({ ...p, capabilities: ['*'] }, ok)), 'FSP-1109');
  assert.equal(code(() => verifyPermit(p, { ...ok, trustedHubs: { [ident.agentId]: ident.publicPem } })), 'FSP-1109');
  assert.equal(code(() => verifyPermit(p, { ...ok, passport: { ...vectors.passport, passport_id: 'pp_' + '0'.repeat(32) } })), 'FSP-1109');
  assert.equal(code(() => verifyPermit(p, { ...ok, now: 1763291800500 })), 'FSP-1110');
  assert.equal(code(() => verifyPermit(p, { ...ok, revoked: [p.permit_id] })), 'FSP-1111');
  assert.equal(code(() => verifyPermit(p, { ...ok, capability: 'payment.send' })), 'FSP-1112');
  assert.equal(code(() => verifyPermit(p, { ...ok, capability: 'fxrate' })), 'FSP-1112');
  assert.equal(code(() => verifyPermit(p, { ...ok, capability: 'invoice.total', scopes: ['invoices:write'] })), 'FSP-1112');
  assert.equal(code(() => verifyPermit(p, { ...ok, capability: 'invoice.total', depth: 2 })), 'FSP-1112');
  assert.equal(code(() => verifyPermit(p, { ...ok, message: true })), 'FSP-1112');
});

test('black box: Merkle, checkpoints, cosignatures and bundles agree with Python', () => {
  // RFC 6962 reference roots.
  const ref = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map((h) => leafHash(Buffer.from(h, 'hex')));
  assert.equal(merkleRoot(ref).toString('hex'), '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328');
  assert.equal(merkleRoot(ref.slice(0, 7)).toString('hex'), 'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c');

  const { bundle, checkpoint_3: cp3 } = vectors.audit;
  const hub = Identity.fromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 128)));
  const witness = Identity.fromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32)));
  verifyCheckpoint(bundle.checkpoint, hub.publicPem);
  verifyCosignature(bundle.cosignatures[0], bundle.checkpoint, witness.publicPem);
  const report = verifyBundle(bundle, { hubPublicKey: hub.publicPem, witnessKeys: { [witness.agentId]: witness.publicPem }, previous: cp3 });
  assert.deepEqual([report.valid, report.entries, report.witnesses, report.extends_previous], [true, 3, [witness.agentId], true]);

  const hex = (h: string) => Buffer.from(h, 'hex');
  const leaf = leafHash(Buffer.from(bundle.entries[0].leaf, 'utf8'));
  const root = hex(bundle.checkpoint.root);
  assert.equal(verifyInclusion(leaf, 1, 5, bundle.proofs['1'].map(hex), root), true);
  assert.equal(verifyInclusion(leaf, 2, 5, bundle.proofs['1'].map(hex), root), false);
  assert.equal(verifyConsistency(3, 5, hex(cp3.root), root, bundle.consistency.proof.map(hex)), true);
  assert.equal(verifyConsistency(3, 5, hex('00'.repeat(32)), root, bundle.consistency.proof.map(hex)), false);

  const clone = () => JSON.parse(JSON.stringify(bundle));
  const edited = clone();
  edited.entries[1].leaf = edited.entries[1].leaf.replace('"masked"', '"allowed"');
  assert.equal(verifyBundle(edited, { hubPublicKey: hub.publicPem }).valid, false);
  const resigned = clone();
  resigned.checkpoint.root = '00'.repeat(32);
  assert.equal(verifyBundle(resigned, { hubPublicKey: hub.publicPem }).valid, false);
  assert.equal(verifyBundle(bundle, { hubPublicKey: witness.publicPem }).valid, false);
  const forgedWitness = clone();
  forgedWitness.cosignatures[0].tree_size = 4;
  assert.equal(verifyBundle(forgedWitness, { hubPublicKey: hub.publicPem }).valid, false);
});
