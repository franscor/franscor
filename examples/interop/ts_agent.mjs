// TypeScript side of the cross-language acceptance test.
// Business logic is plain functions; FRANSCOR only wraps them.
import { createRequire } from 'node:module';
import franscor from '../../packages/sdk-typescript/dist/index.js';

const emit = (event, data) => process.stdout.write(JSON.stringify({ event, data }) + '\n');

// Optional: an in-memory OpenTelemetry pipeline, to prove trace propagation across languages.
let exporter = null;
if (process.env.FRANSCOR_TEST_OTEL) {
  const require = createRequire(new URL('../../packages/sdk-typescript/package.json', import.meta.url));
  const api = require('@opentelemetry/api');
  const { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } = require('@opentelemetry/sdk-trace-base');
  const { W3CTraceContextPropagator } = require('@opentelemetry/core');
  exporter = new InMemorySpanExporter();
  api.trace.setGlobalTracerProvider(new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] }));
  api.propagation.setGlobalPropagator(new W3CTraceContextPropagator());
}
const spans = (name) =>
  (exporter?.getFinishedSpans() ?? []).filter((s) => s.name === name).map((s) => ({
    traceId: s.spanContext().traceId,
    spanId: s.spanContext().spanId,
    parentSpanId: s.parentSpanContext?.spanId ?? null,
    status: s.attributes['franscor.status'],
  }));

// Existing business logic, unchanged.
function analyzeText({ text }) {
  const words = text.trim().split(/\s+/).filter(Boolean);
  return { words: words.length, upper: text.toUpperCase(), avg_len: words.reduce((n, w) => n + w.length, 0) / words.length };
}

franscor.capability('text.analyze', analyzeText, { description: 'Word count and stats', risk: 'R1' });
franscor.capability('ledger.write', () => ({ written: true }), { description: 'Writes to the ledger', risk: 'R4' });

const agent = await franscor.connect({
  name: 'ts-writer',
  approval: async (req) => {
    emit('approval_asked', { capability: req.capability, requester: req.requester.name });
    return false; // nobody approves in this demo
  },
});
emit('connected', { agentId: agent.agentId, capabilities: agent.capabilities, status: agent.status, passport: agent.passport?.passport_id ?? null });

agent.onMessage('rotate', async () => {
  const statement = await agent.rotateKey();
  emit('rotated', { old: statement.old_agent_id, new: agent.agentId, status: agent.status, evidence: agent.evidence.path });
});

agent.onMessage('shutdown', async () => {
  emit('evidence', { path: agent.evidence.path, stats: agent.stats, server_spans: spans('franscor.task') });
  await agent.close(); // no process.exit(): the event loop drains and Node exits cleanly
});

const peers = await agent.discover('math.stats');
emit('discovered', peers.map((p) => ({ name: p.name, language: p.runtime.language })));

const stats = await agent.delegate('math.stats', { values: [1.5, 2.5, 4] });
emit('delegated', { output: stats, client_spans: spans('franscor.delegate') });

try {
  await agent.delegate('admin.reset', {});
  emit('unexpected', 'admin.reset succeeded');
} catch (err) {
  emit('refused', { status: err.status, code: err.code });
}
emit('ready', null);
