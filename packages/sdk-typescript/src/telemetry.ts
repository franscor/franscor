/**
 * Optional OpenTelemetry tracing. Active only if the application has installed
 * `@opentelemetry/api` (FRANSCOR does not depend on it) and registered a tracer
 * provider and a W3C propagator. Same span names and attributes as Python:
 * `franscor.delegate` (client) and `franscor.task` (server); the trace context
 * travels in the signed request body. Never records inputs or outputs.
 */

// Loaded lazily through a variable specifier so TypeScript does not need the package.
let api: any = null;
let tried = false;

export async function loadTelemetry(): Promise<boolean> {
  if (!tried) {
    tried = true;
    const specifier = '@opentelemetry/api';
    try {
      api = await import(specifier);
    } catch {
      api = null;
    }
  }
  return api !== null;
}

export interface SpanHandle {
  setAttribute(key: string, value: string | number): void;
  fail(description: string): void;
  end(): void;
}

const NULL_SPAN: SpanHandle = { setAttribute() {}, fail() {}, end() {} };
const SPAN_KIND_SERVER = 1;
const SPAN_KIND_CLIENT = 2;
const STATUS_ERROR = 2;

function wrap(span: any): SpanHandle {
  return {
    setAttribute: (k, v) => span.setAttribute(k, v),
    fail: (d) => span.setStatus({ code: STATUS_ERROR, message: d }),
    end: () => span.end(),
  };
}

export function clientSpan(name: string, attributes: Record<string, string>): { span: SpanHandle; carrier?: Record<string, string> } {
  if (!api) return { span: NULL_SPAN };
  const span = api.trace.getTracer('franscor').startSpan(name, { kind: SPAN_KIND_CLIENT, attributes });
  const carrier: Record<string, string> = {};
  api.propagation.inject(api.trace.setSpan(api.context.active(), span), carrier);
  return { span: wrap(span), carrier: Object.keys(carrier).length ? carrier : undefined };
}

export function validCarrier(c: unknown): c is Record<string, string> {
  if (!c || typeof c !== 'object' || Array.isArray(c)) return false;
  const entries = Object.entries(c as Record<string, unknown>);
  return entries.length <= 4 && entries.every(([k, v]) => typeof k === 'string' && typeof v === 'string')
    && entries.reduce((n, [k, v]) => n + k.length + String(v).length, 0) <= 512;
}

export function serverSpan(name: string, attributes: Record<string, string>, carrier: unknown): SpanHandle {
  if (!api) return NULL_SPAN;
  const parent = validCarrier(carrier) ? api.propagation.extract(api.context.active(), carrier) : api.context.active();
  return wrap(api.trace.getTracer('franscor').startSpan(name, { kind: SPAN_KIND_SERVER, attributes }, parent));
}
