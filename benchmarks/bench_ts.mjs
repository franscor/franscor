// Measure, don't claim — TypeScript SDK. Needs a running hub:
//   franscor hub --port 7711 --rate 1000000 --burst 1000000
//   FRANSCOR_HUB_URL=ws://127.0.0.1:7711 node franscor/benchmarks/bench_ts.mjs [n] [concurrency]
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, defineCapability } from '../packages/sdk-typescript/dist/index.js';

const n = Number(process.argv[2] ?? 500);
const concurrency = Number(process.argv[3] ?? 32);
const home = mkdtempSync(join(tmpdir(), 'franscor-bench-'));

const t0 = performance.now();
const worker = await connect({ name: 'worker', home: join(home, 'w'), tools: [defineCapability('echo', (x) => x, { risk: 'R0' })] });
const connectMs = performance.now() - t0;
const boss = await connect({ name: 'boss', home: join(home, 'b') });
const to = worker.agentId;

for (let i = 0; i < 20; i++) await boss.delegate('echo', { x: 1 }, { to });

const lat = [];
for (let i = 0; i < n; i++) {
  const s = performance.now();
  await boss.delegate('echo', { i, v: 0.5 }, { to });
  lat.push(performance.now() - s);
}
lat.sort((a, b) => a - b);
const pct = (p) => lat[Math.max(0, Math.ceil(n * p) - 1)].toFixed(2);

let next = 0;
const s = performance.now();
await Promise.all(Array.from({ length: concurrency }, async () => {
  while (next < n) {
    const i = next++;
    await boss.delegate('echo', { i }, { to });
  }
}));
const throughput = n / ((performance.now() - s) / 1000);

console.log(`connect (detect+adapters+identity+handshake): ${connectMs.toFixed(1)} ms`);
console.log(`sequential delegate round-trip, n=${n}: p50 ${pct(0.5)} ms, p95 ${pct(0.95)} ms, p99 ${pct(0.99)} ms`);
console.log(`concurrent delegate throughput (concurrency ${concurrency}): ${throughput.toFixed(0)} tasks/s`);
console.log(`heap used: ${(process.memoryUsage().heapUsed / 1048576).toFixed(1)} MiB`);
await boss.close();
await worker.close();
