#!/usr/bin/env node

import { createHash, timingSafeEqual } from 'crypto';
import http from 'http';
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'http';
import https from 'https';

const apiKey = process.env.MCP_API_KEY;
const listenHost = process.env.MCP_AUTH_HOST || '0.0.0.0';
const listenPort = Number.parseInt(process.env.MCP_AUTH_PORT || '3001', 10);
const upstreamUrl = new URL(process.env.MCP_UPSTREAM_URL || 'http://127.0.0.1:3000');

if (!apiKey) {
  console.error('[auth-gateway] MCP_API_KEY is required');
  process.exit(1);
}

if (apiKey.length < 32) {
  console.error('[auth-gateway] MCP_API_KEY must contain at least 32 characters');
  process.exit(1);
}

if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
  console.error('[auth-gateway] MCP_AUTH_PORT must be a valid TCP port');
  process.exit(1);
}

if (upstreamUrl.protocol !== 'http:' && upstreamUrl.protocol !== 'https:') {
  console.error('[auth-gateway] MCP_UPSTREAM_URL must use http:// or https://');
  process.exit(1);
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

const expectedDigest = digest(apiKey);

function extractCredential(req: IncomingMessage): string | undefined {
  const authorization = req.headers.authorization;
  if (authorization?.startsWith('Bearer ')) {
    return authorization.slice('Bearer '.length).trim();
  }

  const headerKey = req.headers['x-api-key'];
  return Array.isArray(headerKey) ? headerKey[0] : headerKey;
}

function isAuthorized(req: IncomingMessage): boolean {
  const credential = extractCredential(req);
  if (!credential) {
    return false;
  }

  return timingSafeEqual(expectedDigest, digest(credential));
}

function unauthorized(res: ServerResponse): void {
  res.writeHead(401, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'WWW-Authenticate': 'Bearer realm="notebooklm-mcp"',
  });
  res.end(JSON.stringify({ success: false, error: 'Unauthorized' }));
}

function buildUpstreamHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const forwarded = { ...headers };
  delete forwarded.authorization;
  delete forwarded['x-api-key'];
  forwarded.host = upstreamUrl.host;
  forwarded['x-forwarded-proto'] = 'http';
  return forwarded;
}

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, X-API-Key, Content-Type',
      'Access-Control-Max-Age': '600',
    });
    res.end();
    return;
  }

  if (!isAuthorized(req)) {
    unauthorized(res);
    return;
  }

  const targetPath = `${upstreamUrl.pathname.replace(/\/$/, '')}${req.url || '/'}`;
  const transport = upstreamUrl.protocol === 'https:' ? https : http;
  const upstreamReq = transport.request(
    {
      protocol: upstreamUrl.protocol,
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port || undefined,
      method: req.method,
      path: targetPath,
      headers: buildUpstreamHeaders(req.headers),
    },
    (upstreamRes) => {
      const responseHeaders = { ...upstreamRes.headers };
      responseHeaders['access-control-allow-origin'] = '*';
      responseHeaders['cache-control'] = 'no-store';
      res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
      upstreamRes.pipe(res);
    }
  );

  upstreamReq.on('error', (error) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    }
    res.end(JSON.stringify({ success: false, error: `Upstream unavailable: ${error.message}` }));
  });

  req.pipe(upstreamReq);
});

server.listen(listenPort, listenHost, () => {
  console.error(
    `[auth-gateway] Listening on http://${listenHost}:${listenPort} -> ${upstreamUrl.toString()}`
  );
});

function shutdown(): void {
  server.close((error) => {
    if (error) {
      console.error(`[auth-gateway] Shutdown failed: ${error.message}`);
      process.exitCode = 1;
    }
  });
}

process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
