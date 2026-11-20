/** Capabilities: what an agent offers, how risky it is, who handles it. */

export const CAPABILITY_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;

export type Risk = 'R0' | 'R1' | 'R2' | 'R3' | 'R4' | 'R5';

export interface TaskContext {
  taskId: string;
  requester: { agentId: string; name: string; org: string };
  /** Aborted when the deadline expires or the requester cancels. */
  signal: AbortSignal;
}

export type Handler<I = any, O = any> = (input: I, ctx: TaskContext) => O | Promise<O>;

export interface CapabilityOptions {
  description?: string;
  risk?: Risk | number;
  inputSchema?: Record<string, unknown>;
}

export interface Capability {
  name: string;
  handler: Handler;
  description: string;
  risk: number;
  inputSchema?: Record<string, unknown>;
  source: string;
}

export function parseRisk(raw: string | number): number {
  const text = String(raw).trim().toUpperCase().replace(/^R/, '');
  const n = Number(text);
  if (/^\d$/.test(text) && n >= 0 && n <= 5) return n;
  throw new RangeError(`risk must be R0..R5, got ${JSON.stringify(raw)}`);
}

export function defineCapability(name: string, handler: Handler, opts: CapabilityOptions = {}, source = 'function'): Capability {
  if (!CAPABILITY_RE.test(name)) throw new RangeError(`invalid capability name ${JSON.stringify(name)} (lowercase letters, digits, . _ -)`);
  return {
    name,
    handler,
    description: (opts.description ?? '').slice(0, 1000),
    risk: parseRisk(opts.risk ?? 'R1'),
    inputSchema: opts.inputSchema,
    source,
  };
}

export function descriptor(cap: Capability): Record<string, unknown> {
  const out: Record<string, unknown> = { name: cap.name, description: cap.description, risk: `R${cap.risk}` };
  if (cap.inputSchema) out.input_schema = cap.inputSchema;
  return out;
}

export const isCapability = (v: unknown): v is Capability =>
  typeof v === 'object' && v !== null && typeof (v as Capability).name === 'string'
  && typeof (v as Capability).handler === 'function' && typeof (v as Capability).risk === 'number';

const registry = new Map<string, Capability>();

/** Declare a capability. Nothing is exposed until `connect()`. */
export function capability<I = any, O = any>(name: string, handler: Handler<I, O>, opts: CapabilityOptions = {}): Capability {
  const cap = defineCapability(name, handler, opts);
  registry.set(name, cap);
  return cap;
}

export const registered = (): Capability[] => [...registry.values()];
export const clearRegistry = (): void => registry.clear();
