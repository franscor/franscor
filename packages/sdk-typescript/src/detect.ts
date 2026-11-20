/**
 * Environment detection. Reads package.json files only — never imports or
 * runs project code. "Installed" never means "an agent is running".
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export const SDK_VERSION = '0.2.0';

export const FRAMEWORKS: Record<string, { packages: string[]; adapter: 'available' | 'planned' }> = {
  langchain: { packages: ['@langchain/core', 'langchain'], adapter: 'available' },
  langgraph: { packages: ['@langchain/langgraph'], adapter: 'available' },
  'openai-agents': { packages: ['@openai/agents'], adapter: 'planned' },
  'vercel-ai': { packages: ['ai'], adapter: 'planned' },
  mcp: { packages: ['@modelcontextprotocol/sdk'], adapter: 'available' }, // importMcpTools()
  a2a: { packages: ['@a2a-js/sdk'], adapter: 'planned' },
};

function readJson(path: string): Record<string, any> | undefined {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as Record<string, any>;
  } catch {
    return undefined;
  }
}

function findUp(start: string, file: string): string | undefined {
  let dir = resolve(start);
  for (;;) {
    const candidate = join(dir, file);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

function installedVersion(start: string, pkg: string): string | undefined {
  let dir = resolve(start);
  for (;;) {
    const manifest = readJson(join(dir, 'node_modules', pkg, 'package.json'));
    if (manifest?.version) return String(manifest.version);
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

export interface Detection {
  sdk: { name: 'franscor'; version: string; fsp: '0.1' };
  runtime: { language: 'typescript'; version: string; platform: string; webSocket: boolean };
  frameworks: Record<string, { installed: boolean; package: string | null; version: string | null; adapter: string }>;
  config: Record<string, unknown> | null;
  hubUrl: string | null;
  transports: string[];
}

export function detect(cwd = process.cwd()): Detection {
  const frameworks: Detection['frameworks'] = {};
  for (const [name, spec] of Object.entries(FRAMEWORKS)) {
    let found: [string, string] | undefined;
    for (const pkg of spec.packages) {
      const v = installedVersion(cwd, pkg);
      if (v) {
        found = [pkg, v];
        break;
      }
    }
    frameworks[name] = { installed: !!found, package: found?.[0] ?? null, version: found?.[1] ?? null, adapter: spec.adapter };
  }
  const manifestPath = findUp(cwd, 'package.json');
  const config = manifestPath ? (readJson(manifestPath)?.franscor as Record<string, unknown> | undefined) ?? null : null;
  return {
    sdk: { name: 'franscor', version: SDK_VERSION, fsp: '0.1' },
    runtime: { language: 'typescript', version: process.versions.node, platform: process.platform, webSocket: typeof WebSocket === 'function' },
    frameworks,
    config,
    hubUrl: process.env.FRANSCOR_HUB_URL ?? null,
    transports: ['websocket'],
  };
}
