// TypeScript side of the cross-language Permit test: an acme worker behind a
// hub that admits partner agents with permits. Business logic is plain functions.
import franscor from '../../packages/sdk-typescript/dist/index.js';

const emit = (event, data) => process.stdout.write(JSON.stringify({ event, data }) + '\n');

franscor.capability('invoice.total', ({ lines }) => ({ total: lines.reduce((a, b) => a + b, 0) }), { description: 'Sum invoice lines', risk: 'R1' });
franscor.capability('payment.send', ({ amount }) => ({ sent: amount }), { description: 'Send a payment', risk: 'R1' });

const agent = await franscor.connect({
  name: 'ts-ledger',
  org: 'acme',
  visibility: 'public',
  acceptOrgs: ['acme', 'globex'],
});
emit('connected', { agentId: agent.agentId, permitMode: agent.permitMode });

agent.onMessage('shutdown', async () => {
  emit('evidence', { path: agent.evidence.path, stats: agent.stats });
  await agent.close();
});
