/**
 * Adapter engine. Adapters turn existing objects (registered functions,
 * LangChain tools/runnables, compiled LangGraph graphs) into capabilities
 * without changing them. Third-party adapters are passed explicitly via
 * `connect({ adapters })` — nothing is imported implicitly.
 */
import { defineCapability, isCapability, registered, type Capability } from './capabilities.js';
import type { Detection } from './detect.js';

export interface AdapterContext {
  objects: unknown[];
  detection: Detection;
}

export interface Adapter {
  name: string;
  version: string;
  detect(ctx: AdapterContext): boolean;
  capabilities(ctx: AdapterContext): Capability[];
}

export interface AdapterReport {
  adapter: string;
  version?: string;
  active: boolean;
  capabilities?: string[];
  error?: string;
}

export const functionAdapter: Adapter = {
  name: 'functions',
  version: '0.1.0',
  detect: (ctx) => registered().length > 0 || ctx.objects.some(isCapability),
  capabilities: (ctx) => [...registered(), ...ctx.objects.filter(isCapability)],
};

interface RunnableLike {
  name: string;
  description?: string;
  invoke: (input: unknown) => unknown;
  schema?: unknown;
}

const isRunnable = (o: unknown): o is RunnableLike =>
  typeof o === 'object' && o !== null && !isCapability(o)
  && typeof (o as RunnableLike).name === 'string' && typeof (o as RunnableLike).invoke === 'function';

const slug = (text: string) => text.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 100) || 'tool';

/** LangChain.js tools and runnables, duck-typed on `name` + `invoke`. Default risk R2. */
export function langchainAdapter(opts: { defaultRisk?: number; riskOverrides?: Record<string, number> } = {}): Adapter {
  return {
    name: 'langchain',
    version: '0.1.0',
    detect: (ctx) => ctx.objects.some(isRunnable),
    capabilities: (ctx) =>
      ctx.objects.filter(isRunnable).map((tool) => {
        const name = `tool.${slug(tool.name)}`;
        return defineCapability(
          name,
          (input) => tool.invoke(input),
          { description: String(tool.description ?? ''), risk: opts.riskOverrides?.[name] ?? opts.defaultRisk ?? 2 },
          'langchain',
        );
      }),
  };
}

export const builtinAdapters = (): Adapter[] => [functionAdapter, langchainAdapter()];

export function collect(ctx: AdapterContext, adapters: Adapter[]): { caps: Map<string, Capability>; report: AdapterReport[] } {
  const caps = new Map<string, Capability>();
  const report: AdapterReport[] = [];
  for (const adapter of adapters) {
    const entry: AdapterReport = { adapter: adapter.name, version: adapter.version, active: false };
    try {
      if (adapter.detect(ctx)) {
        const found = adapter.capabilities(ctx);
        for (const cap of found) {
          if (caps.has(cap.name)) throw new Error(`duplicate capability ${cap.name}`);
          caps.set(cap.name, cap);
        }
        entry.active = true;
        entry.capabilities = found.map((c) => c.name);
      }
    } catch (err) {
      entry.error = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    }
    report.push(entry);
  }
  return { caps, report };
}
