#!/usr/bin/env node

import { createHash, timingSafeEqual } from 'crypto';
import http from 'http';
import https from 'https';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'http';

type AuthMode = 'api-key' | 'oauth';

const authMode = (process.env.MCP_AUTH_MODE || 'api-key') as AuthMode;
const apiKey = process.env.MCP_API_KEY;
const listenHost = process.env.MCP_AUTH_HOST || '0.0.0.0';
const listenPort = Number.parseInt(process.env.MCP_AUTH_PORT || '3001', 10);
const upstreamUrl = new URL(process.env.MCP_UPSTREAM_URL || 'http://127.0.0.1:3000');
const resourceUrlValue = process.env.MCP_RESOURCE_URL;
const oauthIssuer = process.env.MCP_OAUTH_ISSUER?.replace(/\/$/, '');
const oauthAudience = process.env.MCP_OAUTH_AUDIENCE;
const oauthJwksUrl = process.env.MCP_OAUTH_JWKS_URL;
const requiredScopes = (process.env.MCP_OAUTH_REQUIRED_SCOPES || '')
  .split(/[ ,]+/)
  .map((scope) => scope.trim())
  .filter(Boolean);

if (authMode !== 'api-key' && authMode !== 'oauth') {
  console.error('[auth-gateway] MCP_AUTH_MODE must be api-key or oauth');
  process.exit(1);
}

if (authMode === 'api-key') {
  if (!apiKey) {
    console.error('[auth-gateway] MCP_API_KEY is required in api-key mode');
    process.exit(1);
  }
  if (apiKey.length < 32) {
    console.error('[auth-gateway] MCP_API_KEY must contain at least 32 characters');
    process.exit(1);
  }
}

if (authMode === 'oauth' && (!resourceUrlValue || !oauthIssuer || !oauthAudience || !oauthJwksUrl)) {
  console.error(
    '[auth-gateway] OAuth mode requires MCP_RESOURCE_URL, MCP_OAUTH_ISSUER, ' +
      'MCP_OAUTH_AUDIENCE, and MCP_OAUTH_JWKS_URL'
  );
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

let resourceUrl: URL | undefined;
let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

if (authMode === 'oauth') {
  try {
    resourceUrl = new URL(resourceUrlValue!);
    jwks = createRemoteJWKSet(new URL(oauthJwksUrl!));
  } catch {
    console.error('[auth-gateway] OAuth URLs must be valid absolute URLs');
    process.exit(1);
  }

  if (resourceUrl.protocol !== 'https:' && resourceUrl.hostname !== 'localhost') {
    console.error('[auth-gateway] MCP_RESOURCE_URL must use HTTPS outside localhost');
    process.exit(1);
  }
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

const expectedDigest = apiKey ? digest(apiKey) : undefined;

function extractBearerToken(req: IncomingMessage): string | undefined {
  const authorization = req.headers.authorization;
  if (!authorization?.startsWith('Bearer ')) {
    return undefined;
  }
  return authorization.slice('Bearer '.length).trim();
}

function extractApiKey(req: IncomingMessage): string | undefined {
  const bearer = extractBearerToken(req);
  if (bearer) {
    return bearer;
  }

  const headerKey = req.headers['x-api-key'];
  return Array.isArray(headerKey) ? headerKey[0] : headerKey;
}

function metadataUrl(): string | undefined {
  return resourceUrl ? new URL('/.well-known/oauth-protected-resource', resourceUrl).toString() : undefined;
}

function unauthorized(res: ServerResponse, errorDescription = 'Authorization required'): void {
  const challengeParts = ['Bearer realm="notebooklm-mcp"'];
  const resourceMetadata = metadataUrl();
  if (resourceMetadata) {
    challengeParts.push(`resource_metadata="${resourceMetadata}"`);
  }
  challengeParts.push('error="invalid_token"');
  challengeParts.push(`error_description="${errorDescription.replace(/"/g, "'")}"`);

  res.writeHead(401, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'WWW-Authenticate': challengeParts.join(', '),
  });
  res.end(JSON.stringify({ success: false, error: 'Unauthorized' }));
}

function forbidden(res: ServerResponse, missingScopes: string[]): void {
  res.writeHead(403, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'WWW-Authenticate': `Bearer error="insufficient_scope", scope="${missingScopes.join(' ')}"`,
  });
  res.end(
    JSON.stringify({ success: false, error: 'Insufficient scope', required_scopes: missingScopes })
  );
}

function tokenScopes(payload: JWTPayload): Set<string> {
  const values: string[] = [];
  if (typeof payload.scope === 'string') {
    values.push(...payload.scope.split(/\s+/));
  }

  const scp = payload.scp;
  if (typeof scp === 'string') {
    values.push(...scp.split(/\s+/));
  } else if (Array.isArray(scp)) {
    values.push(...scp.filter((value): value is string => typeof value === 'string'));
  }

  return new Set(values.filter(Boolean));
}

async function authorize(req: IncomingMessage): Promise<
  | { authorized: true }
  | { authorized: false; status: 401; message: string }
  | { authorized: false; status: 403; missingScopes: string[] }
> {
  if (authMode === 'api-key') {
    const credential = extractApiKey(req);
    if (!credential || !expectedDigest) {
      return { authorized: false, status: 401, message: 'Missing API key' };
    }

    return timingSafeEqual(expectedDigest, digest(credential))
      ? { authorized: true }
      : { authorized: false, status: 401, message: 'Invalid API key' };
  }

  const token = extractBearerToken(req);
  if (!token || !jwks) {
    return { authorized: false, status: 401, message: 'Missing bearer token' };
  }

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: oauthIssuer,
      audience: oauthAudience,
    });
    const scopes = tokenScopes(payload);
    const missingScopes = requiredScopes.filter((scope) => !scopes.has(scope));
    if (missingScopes.length > 0) {
      return { authorized: false, status: 403, missingScopes };
    }
    return { authorized: true };
  } catch (error) {
    return {
      authorized: false,
      status: 401,
      message: error instanceof Error ? error.message : 'Invalid access token',
    };
  }
}

function buildUpstreamHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const forwarded = { ...headers };
  delete forwarded.authorization;
  delete forwarded['x-api-key'];
  forwarded.host = upstreamUrl.host;
  forwarded['x-forwarded-proto'] = resourceUrl?.protocol.replace(':', '') || 'http';
  return forwarded;
}

function serveProtectedResourceMetadata(res: ServerResponse): void {
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' });
  res.end(
    JSON.stringify({
      resource: resourceUrl!.toString().replace(/\/$/, ''),
      authorization_servers: [oauthIssuer],
      bearer_methods_supported: ['header'],
      ...(requiredScopes.length > 0 ? { scopes_supported: requiredScopes } : {}),
    })
  );
}

const server = http.createServer(async (req, res) => {
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

  const requestUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  if (authMode === 'oauth' && requestUrl.pathname === '/.well-known/oauth-protected-resource') {
    serveProtectedResourceMetadata(res);
    return;
  }

  const authResult = await authorize(req);
  if (!authResult.authorized) {
    if (authResult.status === 403) {
      forbidden(res, authResult.missingScopes);
    } else {
      unauthorized(res, authResult.message);
    }
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
    `[auth-gateway] mode=${authMode} listening=http://${listenHost}:${listenPort} ` +
      `upstream=${upstreamUrl.toString()}`
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
