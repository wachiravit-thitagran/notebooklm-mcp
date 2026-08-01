#!/usr/bin/env node

function printUsage(): void {
  console.error(`Usage:
  notebooklm-mcp-secure-remote --url <server-url> --api-key <key>

Environment variables:
  NOTEBOOKLM_SERVER_URL  Remote authenticated gateway URL
  MCP_HTTP_URL           Backward-compatible gateway URL
  MCP_API_KEY            API key sent as a Bearer token
  MCP_HTTP_TIMEOUT       HTTP request timeout in milliseconds`);
}

function readFlag(args: string[], names: string[]): string | undefined {
  const index = args.findIndex((arg) => names.includes(arg));
  return index >= 0 ? args[index + 1] : undefined;
}

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  printUsage();
  process.exit(0);
}

const serverUrl =
  readFlag(args, ['--url', '-u']) ||
  process.env.NOTEBOOKLM_SERVER_URL ||
  process.env.MCP_HTTP_URL;
const apiKey = readFlag(args, ['--api-key', '-k']) || process.env.MCP_API_KEY;

if (!serverUrl) {
  console.error('[secure-remote] Missing server URL');
  printUsage();
  process.exit(1);
}

if (!apiKey) {
  console.error('[secure-remote] Missing API key');
  printUsage();
  process.exit(1);
}

let parsedUrl: URL;
try {
  parsedUrl = new URL(serverUrl);
} catch {
  console.error(`[secure-remote] Invalid server URL: ${serverUrl}`);
  process.exit(1);
}

if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
  console.error('[secure-remote] Server URL must use http:// or https://');
  process.exit(1);
}

process.env.MCP_HTTP_URL = parsedUrl.toString().replace(/\/$/, '');

const originalFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const headers = new Headers(init?.headers);
  headers.set('Authorization', `Bearer ${apiKey}`);
  return originalFetch(input, { ...init, headers });
};

await import('../stdio-http-proxy.js');
