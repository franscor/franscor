// Against the official MCP TypeScript SDK (dev dependency only).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { importMcpTools } from '../mcp.js';

test('MCP tools become FSP capabilities with mapped risk', async () => {
  const server = new McpServer({ name: 'Notes', version: '1.0.0' });
  const text = (t: string) => ({ content: [{ type: 'text' as const, text: t }] });
  server.registerTool('read_note', { description: 'Read', annotations: { readOnlyHint: true } }, async () => text(JSON.stringify({ note: 'hi' })));
  server.registerTool('wipe', { description: 'Wipe all', annotations: { destructiveHint: true } }, async () => ({ ...text('done'), structuredContent: { wiped: true } }));
  server.registerTool('broken', { description: 'Fails' }, async () => ({ ...text('secret detail'), isError: true }));

  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: 'franscor-test', version: '0.1.0' });
  await client.connect(b);

  const caps = await importMcpTools(client);
  assert.deepEqual(caps.map((c) => [c.name, c.risk, c.source]), [
    ['mcp.notes.read_note', 1, 'mcp'],
    ['mcp.notes.wipe', 3, 'mcp'],
    ['mcp.notes.broken', 2, 'mcp'],
  ]);
  const ctx = { taskId: 't', requester: { agentId: 'x', name: 'x', org: 'x' }, signal: new AbortController().signal };
  assert.deepEqual(await caps[0]!.handler({}, ctx), { note: 'hi' });
  assert.deepEqual(await caps[1]!.handler({}, ctx), { wiped: true });
  await assert.rejects(Promise.resolve(caps[2]!.handler({}, ctx)), (err: Error) => err.name === 'McpToolError' && !err.message.includes('secret'));
  await client.close();
});
