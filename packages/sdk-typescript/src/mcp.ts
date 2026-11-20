/**
 * MCP import for TypeScript: the tools of a connected MCP client become FSP
 * capabilities. No dependency on the MCP SDK — pass a `Client` from
 * `@modelcontextprotocol/sdk` (or anything with the same `listTools` /
 * `callTool` methods) that you have already connected:
 *
 *   const mcp = new Client({ name: 'franscor', version: '0.1.0' });
 *   await mcp.connect(new StdioClientTransport({ command: 'my-mcp-server' }));
 *   const agent = await franscor.connect({ name: 'files', tools: await importMcpTools(mcp) });
 *
 * Risk: `readOnlyHint` → R1, `destructiveHint` → R3, otherwise R2 (same as Python).
 * Exporting FSP capabilities as an MCP server is done by the Python bridge
 * (`franscor bridge mcp`), which any MCP host can launch.
 */
import { defineCapability, type Capability } from './capabilities.js';

interface McpTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean };
}

interface McpCallResult {
  content?: { type: string; text?: string }[];
  structuredContent?: unknown;
  isError?: boolean;
}

export interface McpClientLike {
  listTools(params?: { cursor?: string }): Promise<{ tools: McpTool[]; nextCursor?: string }>;
  callTool(params: { name: string; arguments?: Record<string, unknown> }): Promise<unknown>;
  getServerVersion?(): { name?: string } | undefined;
}

export interface ImportMcpOptions {
  prefix?: string;
  defaultRisk?: number;
  riskOverrides?: Record<string, number>;
  include?: string[];
}

export class McpToolError extends Error {
  override name = 'McpToolError';
}

const slug = (text: string, limit = 60) =>
  text.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, limit) || 'x';

function riskOf(tool: McpTool, opts: ImportMcpOptions): number {
  if (opts.riskOverrides && tool.name in opts.riskOverrides) return opts.riskOverrides[tool.name]!;
  if (tool.annotations?.destructiveHint) return 3;
  if (tool.annotations?.readOnlyHint) return 1;
  return opts.defaultRisk ?? 2;
}

function decode(result: McpCallResult): unknown {
  if (result.structuredContent !== undefined && result.structuredContent !== null) return result.structuredContent;
  const text = (result.content ?? []).filter((c) => c.type === 'text').map((c) => c.text ?? '').join('\n');
  try {
    return JSON.parse(text);
  } catch {
    return { text };
  }
}

export async function importMcpTools(client: McpClientLike, opts: ImportMcpOptions = {}): Promise<Capability[]> {
  const prefix = slug(opts.prefix ?? client.getServerVersion?.()?.name ?? 'server', 40);
  const caps: Capability[] = [];
  let cursor: string | undefined;
  do {
    const page = await client.listTools(cursor ? { cursor } : undefined);
    for (const tool of page.tools) {
      if (opts.include && !opts.include.includes(tool.name)) continue;
      caps.push(defineCapability(
        `mcp.${prefix}.${slug(tool.name)}`.slice(0, 128),
        async (input: unknown) => {
          const args = input && typeof input === 'object' && !Array.isArray(input) ? (input as Record<string, unknown>) : { input };
          const result = (await client.callTool({ name: tool.name, arguments: args })) as McpCallResult;
          if (result.isError) throw new McpToolError(tool.name);
          return decode(result);
        },
        { description: tool.description ?? tool.name, risk: riskOf(tool, opts), inputSchema: tool.inputSchema },
        'mcp',
      ));
    }
    cursor = page.nextCursor;
  } while (cursor);
  return caps;
}
