/**
 * The agent runtime: `await franscor.connect()` and everything after it.
 * detect -> adapters -> identity -> handshake -> serve / delegate -> reconnect -> close.
 * Uses the WebSocket client built into Node >= 22: zero runtime dependencies.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { builtinAdapters, collect, type Adapter, type AdapterReport } from './adapters.js';
import { canonicalHash } from './canonical.js';
import { descriptor, parseRisk, type Capability, type Risk } from './capabilities.js';
import { detect, SDK_VERSION, type Detection } from './detect.js';
import { FSP_VERSION, seal, verifyEnvelope, type Envelope, type FrameType } from './envelope.js';
import { Codes, FSPError, TaskError, type TaskStatus } from './errors.js';
import { EvidenceLog } from './evidence.js';
import { agentIdFromPem, franscorHome, Identity, NAME_RE } from './identity.js';
import { AgentPolicy } from './policy.js';
import { makeRevocation, makeRotation, type RevocationStatement, type RotationStatement } from './statements.js';
import { clientSpan, loadTelemetry, serverSpan } from './telemetry.js';
import { verifyCrl, verifyPassport, type Passport, type PassportCrl } from './passport.js';
import { requestTerms, verifyPermit } from './permit.js';

/** Delegation depth of the task being served; a handler that delegates sends depth + 1. */
const DEPTH = new AsyncLocalStorage<number>();
const BLOCK_RULES: Record<string, string> = {
  [Codes.PASSPORT_EXPIRED]: 'passport-expired', [Codes.PASSPORT_REVOKED]: 'passport-revoked',
  [Codes.PERMIT_INVALID]: 'permit-invalid', [Codes.PERMIT_EXPIRED]: 'permit-expired',
  [Codes.PERMIT_REVOKED]: 'permit-revoked', [Codes.PERMIT_DENIED]: 'permit-denied', [Codes.MALFORMED]: 'malformed-request',
};
import { aad, cardVerified, encKeyOf, encPublicB64, openSealed, sealPayload, signCard } from './sealing.js';

export const DEFAULT_HUB = 'ws://127.0.0.1:7700';
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
const RESULT_CACHE = 1024;
const SEEN_IDS = 4096;

export type AgentStatus = 'connecting' | 'connected' | 'reconnecting' | 'disconnected' | 'closed';
export type Visibility = 'private' | 'org' | 'public';

export interface AgentCard {
  agent_id: string;
  name: string;
  org: string;
  public_key: string;
  enc_key?: string;
  card_sig?: string;
  capabilities: { name: string; description: string; risk: Risk; input_schema?: Record<string, unknown> }[];
  visibility: Visibility;
  accepts: { orgs: string[]; agents: string[] };
  runtime: { language: string; version: string; sdk: string; adapters?: string[] };
}

export interface ApprovalRequest {
  taskId: string;
  capability: string;
  risk: Risk;
  input: unknown;
  requester: { agentId: string; name: string; org: string };
}

export interface ConnectOptions {
  name?: string;
  hubUrl?: string;
  org?: string;
  /** Existing objects to adapt: capabilities, LangChain tools/runnables, … */
  tools?: unknown[];
  visibility?: Visibility;
  acceptOrgs?: string[];
  acceptAgents?: string[];
  approvalThreshold?: Risk | number;
  approval?: (req: ApprovalRequest) => boolean | Promise<boolean>;
  identity?: Identity;
  home?: string;
  adapters?: Adapter[];
  reconnect?: boolean;
  /** 'auto' (default): encrypt when the peer publishes a verified key; 'required'; 'off'. */
  encryption?: 'auto' | 'required' | 'off';
  /** 'verify' (default): check passports when presented; 'require': refuse tasks without one; 'off'. */
  passport?: 'verify' | 'require' | 'off';
  /** 'verify' (default): check a permit the hub attached; 'require': also refuse agents of other hubs without one; 'off'. */
  permit?: 'verify' | 'require' | 'off';
  allowInsecure?: boolean;
}

export interface DelegateOptions {
  to?: string;
  /** Seconds per attempt. */
  timeout?: number;
  retries?: number;
  /** Data scopes the task needs; across a federation link with permits, each must be permitted. */
  scopes?: string[];
}

interface TaskResultBody {
  task_id: string;
  status: TaskStatus;
  output?: unknown;
  error?: { code: string; message: string };
  evidence_hash?: string;
}

type Waiter<T> = { resolve: (v: T) => void; reject: (e: unknown) => void };

function deferred<T>() {
  let w!: Waiter<T>;
  const promise = new Promise<T>((resolve, reject) => (w = { resolve, reject }));
  return { promise, ...w };
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | typeof TIMEOUT> {
  let timer: NodeJS.Timeout;
  return Promise.race([p, new Promise<typeof TIMEOUT>((r) => (timer = setTimeout(() => r(TIMEOUT), ms)))]).finally(() => clearTimeout(timer));
}
const TIMEOUT = Symbol('timeout');

function requireSecure(url: string, allowInsecure: boolean): void {
  const u = new URL(url);
  if (u.protocol !== 'ws:' && u.protocol !== 'wss:') throw new RangeError(`hub URL must be ws:// or wss://, got ${url}`);
  if (u.protocol === 'ws:' && !LOOPBACK.has(u.hostname) && !allowInsecure) {
    throw new RangeError('refusing plain ws:// to a non-loopback hub; use wss:// or pass allowInsecure: true explicitly');
  }
}

export class Agent {
  status: AgentStatus = 'connecting';
  hubId: string | null = null;
  approvalHandler?: ConnectOptions['approval'];
  /** Outcome counters: tasks this agent delegated and tasks it served, by status. */
  readonly stats: { delegated: Record<string, number>; served: Record<string, number> } = { delegated: {}, served: {} };
  /** Set by connect(): where the identity and evidence live, and whether to persist rotations. */
  home?: string;
  persistIdentity = false;
  encryption: 'auto' | 'required' | 'off' = 'auto';
  passportMode: 'verify' | 'require' | 'off' = 'verify';
  /** This agent's hub-issued passport (FSP 0.2). */
  passport: Passport | null = null;
  permitMode: 'verify' | 'require' | 'off' = 'verify';
  /** Passport issuers trusted by this agent, as announced by its hub: hub_id -> PEM. */
  trustedIssuers: Record<string, string> = {};
  #crls: Record<string, PassportCrl> = {};
  #cards = new Map<string, AgentCard>();

  #ws: WebSocket | null = null;
  #hubPem = '';
  #hubWaiters = new Map<string, Waiter<Envelope>>();
  #taskWaiters = new Map<string, Waiter<TaskResultBody>>();
  #refToTask = new Map<string, string>();
  #results = new Map<string, TaskResultBody>();
  #running = new Map<string, AbortController>();
  #seen = new Set<string>();
  #topicHandlers = new Map<string, (data: unknown, sender: AgentCard) => unknown>();
  #connected = deferred<void>();

  constructor(
    readonly name: string,
    readonly org: string,
    private ident: Identity,
    private readonly caps: Map<string, Capability>,
    readonly policy: AgentPolicy,
    readonly visibility: Visibility,
    readonly hubUrl: string,
    private readonly hubKid: string | undefined,
    public evidence: EvidenceLog,
    readonly adapters: AdapterReport[],
    readonly detection: Detection,
    private readonly reconnect: boolean,
  ) {}

  get agentId(): string {
    return this.ident.agentId;
  }

  get identity() {
    return { agentId: this.ident.agentId, name: this.name, org: this.org, kid: this.ident.kid, publicKey: this.ident.publicPem };
  }

  get capabilities(): string[] {
    return [...this.caps.keys()].sort();
  }

  get card(): AgentCard {
    return signCard({
      agent_id: this.ident.agentId,
      name: this.name,
      org: this.org,
      public_key: this.ident.publicPem,
      enc_key: encPublicB64(this.ident),
      capabilities: [...this.caps.values()].map(descriptor) as AgentCard['capabilities'],
      visibility: this.visibility,
      accepts: this.policy.cardAccepts(),
      runtime: {
        language: 'typescript',
        version: this.detection.runtime.version,
        sdk: `franscor-typescript/${SDK_VERSION}`,
        adapters: this.adapters.filter((a) => a.active).map((a) => a.adapter),
      },
    } as unknown as Record<string, unknown>, this.ident) as unknown as AgentCard;
  }

  #remember(card: AgentCard | undefined): void {
    if (!card || !cardVerified(card)) return;
    this.#cards.delete(card.agent_id);
    this.#cards.set(card.agent_id, card);
    if (this.#cards.size > SEEN_IDS) this.#cards.delete(this.#cards.keys().next().value!);
  }

  async #encKeyFor(agentId: string): Promise<string | undefined> {
    if (this.encryption === 'off') return undefined;
    if (!this.#cards.has(agentId)) await this.discover().catch(() => undefined);
    const key = encKeyOf(this.#cards.get(agentId));
    if (!key && this.encryption === 'required') throw new TaskError('rejected', Codes.ENCRYPTION_REQUIRED, 'recipient has no verified encryption key');
    return key;
  }

  // -- connection -----------------------------------------------------------

  async open(): Promise<void> {
    const ws = new WebSocket(this.hubUrl);
    const frames: string[] = [];
    let notify: (() => void) | null = null;
    const next = async (ms: number): Promise<Envelope> => {
      const deadline = Date.now() + ms;
      while (!frames.length) {
        if (ws.readyState >= WebSocket.CLOSING) throw new FSPError(Codes.MALFORMED, 'hub closed the connection');
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new FSPError(Codes.TIMEOUT, 'hub handshake timed out');
        await withTimeout(new Promise<void>((r) => (notify = r)), remaining);
      }
      return JSON.parse(frames.shift()!) as Envelope;
    };
    const onMessage = (ev: MessageEvent) => {
      frames.push(String(ev.data));
      notify?.();
    };
    ws.addEventListener('message', onMessage);
    ws.addEventListener('close', () => notify?.());
    try {
      const challenge = await next(10_000);
      const hubPem = String((challenge.body as Record<string, unknown>)?.hub_public_key ?? '');
      verifyEnvelope(challenge, hubPem);
      if (challenge.type !== 'challenge') throw new FSPError(Codes.MALFORMED, 'expected challenge');
      if (this.hubKid && challenge.sig.kid !== this.hubKid) throw new FSPError(Codes.BAD_SIGNATURE, 'hub key does not match the pinned FRANSCOR_HUB_KID');
      const versions = (challenge.body as { fsp_versions?: string[] }).fsp_versions ?? [];
      if (!versions.includes(FSP_VERSION)) throw new FSPError(Codes.UNSUPPORTED_VERSION, 'hub does not speak FSP 0.1');
      ws.send(JSON.stringify(seal(this.ident, 'register', { nonce: (challenge.body as { nonce: string }).nonce, card: this.card })));
      const reply = await next(10_000);
      verifyEnvelope(reply, hubPem);
      if (reply.type === 'error') {
        const b = reply.body as { code?: string; message?: string };
        throw new FSPError(b.code ?? Codes.MALFORMED, b.message ?? 'registration refused');
      }
      if (reply.type !== 'welcome') throw new FSPError(Codes.MALFORMED, 'expected welcome');
      this.#hubPem = hubPem;
      this.hubId = challenge.from;
      this.passport = ((reply.body as { passport?: Passport }).passport ?? null);
      this.#applyTrust(reply.body as Record<string, unknown>);
    } catch (err) {
      ws.close();
      throw err;
    } finally {
      ws.removeEventListener('message', onMessage);
    }
    this.#ws = ws;
    this.status = 'connected';
    ws.addEventListener('message', (ev) => void this.#onFrame(String(ev.data)));
    ws.addEventListener('close', () => this.#onClose(ws));
    this.#connected.resolve();
  }

  #onClose(ws: WebSocket): void {
    if (this.#ws !== ws) return;
    this.#connected = deferred<void>();
    for (const w of this.#hubWaiters.values()) w.reject(new Error('connection to hub lost'));
    this.#hubWaiters.clear();
    if (this.status === 'closed') return;
    if (this.reconnect) {
      this.status = 'reconnecting';
      void this.#reconnectLoop();
    } else {
      this.status = 'disconnected';
    }
  }

  async #reconnectLoop(): Promise<void> {
    let delay = 500;
    while (this.status === 'reconnecting') {
      await new Promise((r) => setTimeout(r, delay + Math.random() * (delay / 2)));
      try {
        await this.open();
        return;
      } catch {
        delay = Math.min(delay * 2, 10_000);
      }
    }
  }

  async #send(env: Envelope<any>): Promise<void> {
    if (this.status !== 'connected') {
      if (await withTimeout(this.#connected.promise, 10_000) === TIMEOUT) throw new FSPError(Codes.OFFLINE, 'not connected to hub');
    }
    this.#ws!.send(JSON.stringify(env));
  }

  async close(): Promise<void> {
    this.status = 'closed';
    for (const c of this.#running.values()) c.abort();
    const ws = this.#ws;
    if (ws && ws.readyState < WebSocket.CLOSING) {
      await new Promise<void>((r) => {
        const timer = setTimeout(r, 2000);
        ws.addEventListener('close', () => {
          clearTimeout(timer);
          r();
        });
        ws.close();
      });
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  // -- hub requests ---------------------------------------------------------

  async #hubRequest(type: FrameType, body: Record<string, unknown>, timeoutMs: number): Promise<Envelope> {
    const env = seal(this.ident, type, body);
    const d = deferred<Envelope>();
    this.#hubWaiters.set(env.id, d);
    try {
      await this.#send(env);
      const r = await withTimeout(d.promise, timeoutMs);
      if (r === TIMEOUT) throw new FSPError(Codes.TIMEOUT, `${type} timed out`);
      return r;
    } finally {
      this.#hubWaiters.delete(env.id);
    }
  }

  async discover(capability?: string, opts: { org?: string; timeout?: number } = {}): Promise<AgentCard[]> {
    const body: Record<string, unknown> = {};
    if (capability) body.capability = capability;
    if (opts.org) body.org = opts.org;
    const reply = await this.#hubRequest('discover', body, (opts.timeout ?? 5) * 1000);
    const agents = ((reply.body as { agents?: AgentCard[] }).agents ?? []).filter((a) => cardVerified(a));
    for (const a of agents) this.#remember(a);
    return agents;
  }

  // -- messaging ------------------------------------------------------------

  onMessage(topic: string, handler: (data: unknown, sender: AgentCard) => unknown): void {
    this.#topicHandlers.set(topic, handler);
  }

  async send(to: string, topic: string, data: unknown = null): Promise<void> {
    const key = await this.#encKeyFor(to);
    const body: Record<string, unknown> = key
      ? { topic, sealed: sealPayload(data, key, aad('message', this.agentId, to, `message:${topic}`)) }
      : { topic, data };
    const passport = await this.#currentPassport();
    if (passport) body.passport = passport;
    await this.#send(seal(this.ident, 'message', body, { to }));
  }

  // -- delegation (requester) ----------------------------------------------

  /** Run `capability` on another agent; resolves with its output or throws TaskError. */
  async delegate<O = unknown>(capability: string, input: unknown = null, opts: DelegateOptions = {}): Promise<O> {
    const timeout = opts.timeout ?? 30;
    const retries = opts.retries ?? 1;
    let to = opts.to;
    if (!to) {
      const candidates = (await this.discover(capability)).filter((a) => a.agent_id !== this.agentId);
      if (!candidates.length) throw new TaskError('rejected', Codes.OFFLINE, `no reachable agent offers ${capability}`);
      to = candidates[0]!.agent_id;
    }
    const taskId = randomUUID();
    const { span, carrier } = clientSpan('franscor.delegate', { 'franscor.capability': capability, 'franscor.task_id': taskId, 'franscor.peer': to });
    let status = 'failed';
    try {
      const out = await this.#delegate<O>(capability, input, to, taskId, timeout, retries, carrier, opts.scopes ?? []);
      status = 'completed';
      return out;
    } catch (err) {
      if (err instanceof TaskError) {
        status = err.status;
        span.fail(err.code);
      }
      throw err;
    } finally {
      span.setAttribute('franscor.status', status);
      span.end();
      this.#count('delegated', status);
    }
  }

  #count(kind: 'delegated' | 'served', status: string): void {
    this.stats[kind][status] = (this.stats[kind][status] ?? 0) + 1;
  }

  async #delegate<O>(capability: string, input: unknown, to: string, taskId: string, timeout: number, retries: number, carrier?: Record<string, string>, scopes: string[] = []): Promise<O> {
    const deadlineMs = Math.min(3_600_000, Math.max(1, Math.round(timeout * 1000 * (retries + 1))));
    const key = await this.#encKeyFor(to);
    const payload = key ? { sealed: sealPayload(input, key, aad('task.request', this.agentId, to, taskId)) } : { input };
    const passport = await this.#currentPassport();
    const depth = DEPTH.getStore() ?? 0;
    const d = deferred<TaskResultBody>();
    this.#taskWaiters.set(taskId, d);
    let body: TaskResultBody | undefined;
    try {
      for (let attempt = 0; attempt <= retries && !body; attempt++) {
        const env = seal(this.ident, 'task.request', { task_id: taskId, capability, ...payload, deadline_ms: deadlineMs, ...(carrier ? { trace: carrier } : {}), ...(passport ? { passport } : {}), ...(scopes.length ? { scopes } : {}), ...(depth ? { depth } : {}) }, { to });
        this.#refToTask.set(env.id, taskId);
        await this.#send(env);
        const r = await withTimeout(d.promise, timeout * 1000);
        if (r !== TIMEOUT) body = r;
      }
      if (!body) {
        await this.#send(seal(this.ident, 'task.cancel', { task_id: taskId }, { to })).catch(() => undefined);
        throw new TaskError('timeout', Codes.TIMEOUT, `no result after ${timeout}s`, taskId);
      }
    } finally {
      this.#taskWaiters.delete(taskId);
    }
    if (body.status === 'completed') {
      const sealed = (body as unknown as { sealed?: unknown }).sealed;
      if (sealed !== undefined) {
        try {
          return openSealed(sealed, this.ident, aad('task.result', to, this.agentId, taskId)) as O;
        } catch (err) {
          throw new TaskError('failed', (err as FSPError).code ?? Codes.BAD_SIGNATURE, 'cannot open result', taskId);
        }
      }
      if (key) throw new TaskError('failed', Codes.ENCRYPTION_REQUIRED, 'result was not encrypted', taskId);
      return body.output as O;
    }
    throw new TaskError(body.status ?? 'failed', body.error?.code ?? Codes.HANDLER_FAILED, body.error?.message ?? 'task failed', taskId);
  }

  // -- dispatch -------------------------------------------------------------

  async #onFrame(raw: string): Promise<void> {
    let frame: Envelope;
    try {
      frame = JSON.parse(raw) as Envelope;
      verifyEnvelope(frame, this.#hubPem);
    } catch {
      return; // unsigned or tampered frame from the hub: dropped
    }
    const corr = frame.corr ?? '';
    if (frame.type === 'passport.trust') {
      this.#applyTrust(frame.body as Record<string, unknown>);
      return;
    }
    if ((frame.type === 'discover.result' || frame.type === 'identity.ack' || frame.type === 'passport.issued' || frame.type === 'error') && this.#hubWaiters.has(corr)) {
      const w = this.#hubWaiters.get(corr)!;
      if (frame.type === 'error') {
        const b = frame.body as { code?: string; message?: string };
        w.reject(new FSPError(b.code ?? Codes.MALFORMED, b.message ?? ''));
      } else w.resolve(frame);
      return;
    }
    if (frame.type === 'routed') {
      const b = frame.body as { ref?: string; status?: string };
      const taskId = this.#refToTask.get(b.ref ?? '');
      this.#refToTask.delete(b.ref ?? '');
      if (taskId && (b.status === 'offline' || b.status === 'denied')) {
        this.#taskWaiters.get(taskId)?.resolve({
          task_id: taskId,
          status: 'rejected',
          error: { code: b.status === 'offline' ? Codes.OFFLINE : Codes.DENIED, message: `recipient ${b.status}` },
        });
      }
      return;
    }
    if (frame.type !== 'deliver') return;
    const { envelope: inner, sender, permit } = frame.body as { envelope: Envelope; sender: AgentCard; permit?: unknown };
    try {
      if (!sender || typeof sender !== 'object') throw new Error('no sender');
      verifyEnvelope(inner, sender.public_key);
      if (sender.agent_id !== inner.from || inner.to !== this.agentId) throw new Error('mismatch');
    } catch {
      return;
    }
    if (this.#seen.has(inner.id)) return;
    this.#seen.add(inner.id);
    this.#remember(sender);
    if (this.#seen.size > SEEN_IDS) this.#seen.delete(this.#seen.values().next().value!);

    const body = inner.body as Record<string, unknown>;
    switch (inner.type) {
      case 'task.request':
        await this.#serveTask(inner, sender, permit);
        break;
      case 'task.result':
        this.#taskWaiters.get(String(body.task_id))?.resolve(body as unknown as TaskResultBody);
        break;
      case 'task.cancel':
        this.#running.get(`${inner.from}:${String(body.task_id)}`)?.abort();
        break;
      case 'message': {
        const h = this.#topicHandlers.get(String(body.topic));
        if (h) {
          let data = body.data;
          if (body.sealed !== undefined) {
            try {
              data = openSealed(body.sealed, this.ident, aad('message', inner.from, this.agentId, `message:${String(body.topic)}`));
            } catch {
              return;
            }
          }
          await h(data, sender);
        }
        break;
      }
      default:
        break;
    }
  }

  // -- delegation (receiver) ------------------------------------------------

  async #serveTask(env: Envelope, sender: AgentCard, permit?: unknown): Promise<void> {
    const b = env.body as Record<string, unknown>;
    const span = serverSpan('franscor.task', { 'franscor.capability': String(b.capability), 'franscor.task_id': String(b.task_id), 'franscor.peer': env.from }, b.trace);
    try {
      const result = await this.#serveTaskInner(env, sender, permit);
      if (result) {
        span.setAttribute('franscor.status', result.status);
        if (result.status !== 'completed') span.fail(result.error?.code ?? '');
        this.#count('served', result.status);
      }
    } finally {
      span.end();
    }
  }

  /** Exposed for attack tests: what the agent does with a delivered task and an attached permit. */
  serveTaskForTest(env: Envelope, sender: AgentCard, permit?: unknown): Promise<TaskResultBody | undefined> {
    return this.#serveTaskInner(env, sender, permit);
  }

  async #serveTaskInner(env: Envelope, sender: AgentCard, permit?: unknown): Promise<TaskResultBody | undefined> {
    const body = env.body as { task_id?: unknown; capability?: unknown; deadline_ms?: unknown; input?: unknown; sealed?: unknown };
    const taskId = body.task_id;
    const capName = body.capability;
    const deadline = body.deadline_ms;
    if (typeof taskId !== 'string' || typeof capName !== 'string' || !Number.isInteger(deadline) || (deadline as number) <= 0 || (deadline as number) > 3_600_000) return;
    const key = `${env.from}:${taskId}`;
    const cached = this.#results.get(key);
    if (cached) {
      await this.#reply(env, cached);
      return undefined;
    }
    if (this.#running.has(key)) return undefined;

    const cap = this.caps.get(capName);
    let passportId: string | undefined;
    let blockCode: string | undefined;
    let blockRule: string | undefined;
    let attested: AgentCard = sender;
    let verified: Passport | undefined;
    const presented = (env.body as { passport?: unknown }).passport;
    if (this.passportMode !== 'off' && presented !== undefined) {
      try {
        verified = verifyPassport(presented, { trustedHubs: this.trustedIssuers, crls: this.#crls, agentId: env.from });
        passportId = verified.passport_id;
        attested = { ...sender, org: verified.org }; // hub-attested organization
      } catch (err) {
        blockCode = (err as FSPError).code ?? Codes.PASSPORT_INVALID;
      }
    } else if (this.passportMode === 'require') {
      blockCode = Codes.PASSPORT_INVALID;
    }
    let permitId: string | undefined;
    let depth = 0;
    if (!blockCode && this.passportMode !== 'off' && this.permitMode !== 'off') {
      try {
        const terms = requestTerms(env.body as Record<string, unknown>);
        depth = terms.depth;
        if (permit !== undefined && permit !== null) {
          if (!verified) throw new FSPError(Codes.PERMIT_INVALID, 'a permit needs the passport it is bound to');
          // Only our own hub issues the permits we honour.
          const p = verifyPermit(permit, {
            trustedHubs: this.hubId && this.#hubPem ? { [this.hubId]: this.#hubPem } : {},
            agentId: env.from, passport: verified, capability: capName, scopes: terms.scopes, depth,
          });
          permitId = p.permit_id;
        } else if (this.permitMode === 'require' && (!verified || verified.hub_id !== this.hubId)) {
          blockRule = 'permit-required';
          throw new FSPError(Codes.PERMIT_INVALID, 'agents of other hubs need a permit');
        }
      } catch (err) {
        blockCode = (err as FSPError).code ?? Codes.PERMIT_INVALID;
      }
    }
    let [decision, rule] = this.policy.decide(attested, cap);
    if (blockCode) {
      decision = 'block';
      rule = blockRule ?? BLOCK_RULES[blockCode] ?? (presented !== undefined ? 'passport-invalid' : 'passport-required');
    }
    let taskInput: unknown = body.input ?? null;
    if (body.sealed !== undefined) {
      try {
        taskInput = openSealed(body.sealed, this.ident, aad('task.request', env.from, this.agentId, taskId));
      } catch {
        [decision, rule, taskInput] = ['block', 'undecryptable-payload', null];
      }
    } else if (this.encryption === 'required' && !blockCode) {
      [decision, rule] = ['block', 'plaintext-refused'];
    }
    const common = {
      agentId: this.agentId, org: this.org, capability: capName, risk: cap?.risk ?? 0,
      taskId, requester: env.from, inputHash: canonicalHash(taskInput), passportId, permitId,
    };
    const requester = { agentId: sender.agent_id, name: sender.name, org: sender.org };

    if (decision === 'block') {
      const rec = this.evidence.append({ ...common, decision: 'block', rule, status: 'blocked' });
      return this.#finish(env, key, {
        task_id: taskId, status: 'rejected',
        error: {
          code: blockCode ? blockCode : !cap ? Codes.UNKNOWN_CAPABILITY : rule === 'undecryptable-payload' ? Codes.BAD_SIGNATURE : rule === 'plaintext-refused' ? Codes.ENCRYPTION_REQUIRED : Codes.DENIED,
          message: rule,
        },
        evidence_hash: rec.evidence.hash,
      });
    }
    if (decision === 'approval') {
      let approved = false;
      if (this.approvalHandler) {
        try {
          approved = !!(await this.approvalHandler({ taskId, capability: capName, risk: `R${cap!.risk}` as Risk, input: taskInput, requester }));
        } catch {
          approved = false;
        }
      }
      if (!approved) {
        const rec = this.evidence.append({ ...common, decision: 'approval', rule, status: 'approval_rejected' });
        return this.#finish(env, key, {
          task_id: taskId, status: 'approval_rejected',
          error: { code: Codes.APPROVAL_REJECTED, message: 'human approval required and not granted' },
          evidence_hash: rec.evidence.hash,
        });
      }
    }

    const controller = new AbortController();
    this.#running.set(key, controller);
    const timer = setTimeout(() => controller.abort(new FSPError(Codes.TIMEOUT, 'deadline exceeded')), deadline as number);
    let result: TaskResultBody;
    try {
      const aborted = new Promise<never>((_, reject) => controller.signal.addEventListener('abort', () => reject(controller.signal.reason ?? new Error('cancelled')), { once: true }));
      const run = DEPTH.run(depth + 1, () => Promise.resolve(cap!.handler(taskInput, { taskId, requester, signal: controller.signal })));
      const output = await Promise.race([run, aborted]);
      const responseHash = canonicalHash(output ?? null);
      const rec = this.evidence.append({ ...common, decision, rule, status: 'executed', responseHash });
      result = { task_id: taskId, status: 'completed', output: output ?? null, evidence_hash: rec.evidence.hash };
    } catch (err) {
      const rec = this.evidence.append({ ...common, decision, rule, status: 'failed' });
      const isTimeout = err instanceof FSPError && err.code === Codes.TIMEOUT;
      const cancelled = controller.signal.aborted && !isTimeout;
      result = {
        task_id: taskId,
        status: isTimeout ? 'timeout' : cancelled ? 'cancelled' : 'failed',
        // Error class only: messages can carry sensitive data.
        error: { code: isTimeout ? Codes.TIMEOUT : Codes.HANDLER_FAILED, message: isTimeout ? 'deadline exceeded' : cancelled ? 'cancelled by requester' : (err instanceof Error ? err.name : 'Error') },
        evidence_hash: rec.evidence.hash,
      };
    } finally {
      clearTimeout(timer);
      this.#running.delete(key);
    }
    if (this.status === 'closed') return undefined;
    return this.#finish(env, key, result);
  }

  async #finish(env: Envelope, key: string, result: TaskResultBody): Promise<TaskResultBody> {
    this.#results.set(key, result);
    if (this.#results.size > RESULT_CACHE) this.#results.delete(this.#results.keys().next().value!);
    await this.#reply(env, result);
    return result;
  }

  // -- passports --------------------------------------------------------------

  #applyTrust(body: Record<string, unknown>): void {
    const issuers = body.issuers as Record<string, string> | undefined;
    if (issuers && typeof issuers === 'object') {
      const clean: Record<string, string> = {};
      for (const [hubId, pem] of Object.entries(issuers)) {
        try {
          if (agentIdFromPem(pem) === hubId) clean[hubId] = pem;
        } catch {
          /* ignore unreadable keys */
        }
      }
      this.trustedIssuers = clean;
      for (const h of Object.keys(this.#crls)) if (!(h in clean)) delete this.#crls[h];
    }
    for (const crl of (body.crls as PassportCrl[] | undefined) ?? []) {
      const pem = crl && this.trustedIssuers[crl.hub_id];
      if (!pem) continue;
      try {
        verifyCrl(crl, pem);
        if (crl.serial >= (this.#crls[crl.hub_id]?.serial ?? -1)) this.#crls[crl.hub_id] = crl;
      } catch {
        /* forged or foreign CRL: ignored */
      }
    }
  }

  /** CRLs received from the hub, verified (hub_id -> CRL). */
  get crls(): Record<string, PassportCrl> {
    return { ...this.#crls };
  }

  /** Our passport, renewed when less than 10 % (min 5 s) of its life remains. */
  async #currentPassport(): Promise<Passport | null> {
    if (this.passportMode === 'off' || !this.passport) return null;
    const p = this.passport;
    const margin = Math.max(5_000, Math.floor((p.expires_at - p.issued_at) / 10));
    if (p.expires_at - Date.now() < margin) {
      try {
        const reply = await this.#hubRequest('passport.renew', {}, 5_000);
        const fresh = (reply.body as { passport?: Passport }).passport;
        if (fresh) this.passport = fresh;
      } catch {
        /* keep the current one; the receiver decides */
      }
    }
    return this.passport;
  }

  // -- identity lifecycle -----------------------------------------------------

  /**
   * Replace this agent's key; returns the signed rotation statement. The hub
   * refuses the old ID from now on, the new key is persisted (old file kept as
   * `<name>.key.rotated-<ms>`) and the agent reconnects under its new ID.
   */
  async rotateKey(timeout = 10): Promise<RotationStatement> {
    const next = Identity.generate();
    const statement = makeRotation(this.ident, next);
    const reply = await this.#hubRequest('identity.rotate', { statement }, timeout * 1000);
    if ((reply.body as { status?: string }).status !== 'rotated') throw new FSPError(Codes.MALFORMED, 'hub did not confirm the rotation');
    if (this.persistIdentity) next.save(this.name, { home: this.home, replace: true });
    this.ident = next;
    if (this.home) this.evidence = new EvidenceLog(join(this.home, 'evidence', `${next.agentId.slice(4)}.jsonl`), next, this.org);
    const ws = this.#ws!;
    this.#ws = null; // detach: the close handler must not trigger a reconnect with the old key
    this.status = 'connecting';
    this.#connected = deferred<void>();
    // Wait for the closing handshake: reopening while the old socket is still
    // closing trips a libuv assertion on Windows at process exit.
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 2000);
      ws.addEventListener('close', () => {
        clearTimeout(timer);
        resolve();
      });
      ws.close();
    });
    await this.open();
    return statement;
  }

  /** Permanently take this agent's key out of service on the hub, then close. */
  async revokeKey(reason = 'unspecified', timeout = 10): Promise<RevocationStatement> {
    const statement = makeRevocation(this.ident, reason);
    const reply = await this.#hubRequest('identity.revoke', { statement }, timeout * 1000);
    if ((reply.body as { status?: string }).status !== 'revoked') throw new FSPError(Codes.MALFORMED, 'hub did not confirm the revocation');
    await this.close();
    return statement;
  }

  async #reply(env: Envelope, result: TaskResultBody): Promise<void> {
    if ('output' in result && (env.body as { sealed?: unknown }).sealed !== undefined) {
      // Encrypted request -> encrypted result, to the requester's verified key.
      const key = encKeyOf(this.#cards.get(env.from));
      const { output, ...rest } = result;
      result = (key
        ? { ...rest, sealed: sealPayload(output ?? null, key, aad('task.result', this.agentId, env.from, result.task_id)) }
        : { ...rest, status: 'failed', error: { code: Codes.ENCRYPTION_REQUIRED, message: 'no key to encrypt the result' } }) as TaskResultBody;
    }
    try {
      await this.#send(seal(this.ident, 'task.result', result as unknown as Record<string, unknown>, { to: env.from, corr: env.id }));
    } catch {
      /* requester will retry with the same task id and get the cached result */
    }
  }
}

/** Detect, adapt, identify, register and connect — in that order. */
export async function connect(opts: ConnectOptions = {}): Promise<Agent> {
  const detection = detect();
  const cfg = (detection.config ?? {}) as Record<string, any>;
  const env = process.env;
  const rawName = opts.name ?? env.FRANSCOR_NAME ?? cfg.name ?? 'agent';
  const name = String(rawName).toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 64);
  if (!NAME_RE.test(name)) throw new RangeError(`invalid agent name ${JSON.stringify(name)}`);
  const org = opts.org ?? env.FRANSCOR_ORG ?? cfg.org ?? 'local';
  const hubUrl = opts.hubUrl ?? env.FRANSCOR_HUB_URL ?? cfg.hubUrl ?? DEFAULT_HUB;
  const visibility = (opts.visibility ?? env.FRANSCOR_VISIBILITY ?? cfg.visibility ?? 'org') as Visibility;
  if (!['private', 'org', 'public'].includes(visibility)) throw new RangeError('visibility must be private, org or public');
  requireSecure(hubUrl, opts.allowInsecure ?? false);
  if (typeof WebSocket !== 'function') throw new Error('franscor needs Node.js >= 22 (built-in WebSocket)');
  await loadTelemetry();
  const home = opts.home ?? franscorHome();

  const adapters = opts.adapters ? [...builtinAdapters(), ...opts.adapters] : builtinAdapters();
  const { caps, report } = collect({ objects: opts.tools ?? [], detection }, adapters);
  const ident = opts.identity ?? Identity.loadOrCreate(name, home);
  const policy = new AgentPolicy(org, opts.acceptOrgs ?? cfg.acceptOrgs ?? [], opts.acceptAgents ?? cfg.acceptAgents ?? [], parseRisk(opts.approvalThreshold ?? cfg.approvalThreshold ?? 'R4'));
  const evidence = new EvidenceLog(join(home, 'evidence', `${ident.agentId.slice(4)}.jsonl`), ident, org);
  const agent = new Agent(name, org, ident, caps, policy, visibility, hubUrl, env.FRANSCOR_HUB_KID, evidence, report, detection, opts.reconnect ?? true);
  agent.approvalHandler = opts.approval;
  agent.home = home;
  agent.persistIdentity = !opts.identity;
  agent.passportMode = (opts.passport ?? (env.FRANSCOR_PASSPORT as ConnectOptions['passport']) ?? 'verify');
  if (!['verify', 'require', 'off'].includes(agent.passportMode)) throw new RangeError('passport must be verify, require or off');
  agent.permitMode = (opts.permit ?? (env.FRANSCOR_PERMIT as ConnectOptions['permit']) ?? 'verify');
  if (!['verify', 'require', 'off'].includes(agent.permitMode)) throw new RangeError('permit must be verify, require or off');
  agent.encryption = (opts.encryption ?? (env.FRANSCOR_ENCRYPTION as ConnectOptions['encryption']) ?? 'auto');
  if (!['auto', 'required', 'off'].includes(agent.encryption)) throw new RangeError('encryption must be auto, required or off');
  await agent.open();
  return agent;
}
