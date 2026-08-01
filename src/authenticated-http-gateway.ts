#!/usr/bin/env node

import { createHash, timingSafeEqual } from 'crypto';
import http from 'http';
import https from 'https';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'http';

type AuthMode = 'api-key' | 'oauth';
type OAuthTokenMode = 'jwt' | 'introspection';

type IntrospectionResponse = {
  active?: boolean;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  scope?: string;
  scp?: string | string[];
};

type AuthorizationResult =
  | { authorized: true }
  | { authorized: false; status: 401; reason: 'missing' | 'invalid'; description?: string }
  | { authorized: false; status: 403; missingScopes: string[] };

const authMode = (process.env.MCP_AUTH_MODE || 'api-key') as AuthMode;
const tokenMode = (process.env.MCP_OAUTH_TOKEN_MODE || 'jwt') as OAuthTokenMode;
const apiKey = process.env.MCP_API_KEY;
const listenHost = process.env.MCP_AUTH_HOST || '0.0.0.0';
const listenPort = Number.parseInt(process.env.MCP_AUTH_PORT || '3001', 10);
const upstreamUrl = new URL(process.env.MCP_UPSTREAM_URL || 'http://127.0.0.1:3000');
const resourceUrlValue = process.env.MCP_RESOURCE_URL;
const oauthIssuer = process.env.MCP_OAUTH_ISSUER?.replace(/\/$/, '');
const oauthAudience = process.env.MCP_OAUTH_AUDIENCE;
const oauthJwksUrl = process.env.MCP_OAUTH_JWKS_URL;
const introspectionUrl = process.env.MCP_OAUTH_INTROSPECTION_URL;
const introspectionClientId = process.env.MCP_OAUTH_INTROSPECTION_CLIENT_ID;
const introspectionClientSecret = process.env.MCP_OAUTH_INTROSPECTION_CLIENT_SECRET;
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

if (authMode === 'oauth') {
  if (!resourceUrlValue || !oauthIssuer || !oauthAudience) {
    console.error(
      '[auth-gateway] OAuth mode requires MCP_RESOURCE_URL, MCP_OAUTH_ISSUER, and MCP_OAUTH_AUDIENCE'
    );
    process.exit(1);
  }

  if (tokenMode !== 'jwt' && tokenMode !== 'introspection') {
    console.error('[auth-gateway] MCP_OAUTH_TOKEN_MODE must be jwt or introspection');
    process.exit(1);
  }

  if (tokenMode === 'jwt' && !oauthJwksUrl) {
    console.error('[auth-gateway] JWT mode requires MCP_OAUTH_JWKS_URL');
    process.exit(1);
  }

  if (tokenMode === 'introspection' && !introspectionUrl) {
    console.error('[auth-gateway] Introspection mode requires MCP_OAUTH_INTROSPECTION_URL');
    process.exit(1);
  }
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
    if (tokenMode === 'jwt') {
      jwks = createRemoteJWKSet(new URL(oauthJwksUrl!));
    }
    if (tokenMode === 'introspection') {
      new URL(introspectionUrl!);
    }
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
  if (!authorization) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1]?.trim();
}

function extractApiKey(req: IncomingMessage): string | undefined {
  const bearer = extractBearerToken(req);
  if (bearer) return bearer;
  const headerKey = req.headers['x-api-key'];
  return Array.isArray(headerKey) ? headerKey[0] : headerKey;
}

function protectedResourceMetadataUrl(): string | undefined {
  if (!resourceUrl) return undefined;
  const path = resourceUrl.pathname === '/' ? '' : resourceUrl.pathname.replace(/\/$/, '');
  return new URL(`/.well-known/oauth-protected-resource${path}`, resourceUrl.origin).toString();
}

function bearerChallenge(options?: {
  error?: string;
  description?: string;
  scopes?: string[];
}): string {
  const parts = ['Bearer realm="notebooklm-mcp"'];
  const metadata = protectedResourceMetadataUrl();
  if (metadata) parts.push(`resource_metadata="${metadata}"`);
  const scopes = options?.scopes ?? requiredScopes;
  if (scopes.length > 0) parts.push(`scope="${scopes.join(' ')}"`);
  if (options?.error) parts.push(`error="${options.error}"`);
  if (options?.description) {
    parts.push(`error_description="${options.description.replace(/["\\]/g, "'")}"`);
  }
  return parts.join(', ');
}

function unauthorized(
  res: ServerResponse,
  reason: 'missing' | 'invalid',
  description?: string
): void {
  res.writeHead(401, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'WWW-Authenticate': bearerChallenge(
      reason === 'invalid' ? { error: 'invalid_token', description } : undefined
    ),
  });
  res.end(JSON.stringify({ success: false, error: 'Unauthorized' }));
}

function forbidden(res: ServerResponse, missingScopes: string[]): void {
  res.writeHead(403, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'WWW-Authenticate': bearerChallenge({
      error: 'insufficient_scope',
      description: 'The access token does not include the required scope',
      scopes: missingScopes,
    }),
  });
  res.end(
    JSON.stringify({ success: false, error: 'Insufficient scope', required_scopes: missingScopes })
  );
}

function tokenScopes(payload: { scope?: unknown; scp?: unknown }): Set<string> {
  const values: string[] = [];
  if (typeof payload.scope === 'string') values.push(...payload.scope.split(/\s+/));
  if (typeof payload.scp === 'string') values.push(...payload.scp.split(/\s+/));
  if (Array.isArray(payload.scp)) {
    values.push(...payload.scp.filter((value): value is string => typeof value === 'string'));
  }
  return new Set(values.filter(Boolean));
}

function audienceMatches(audience: unknown): boolean {
  if (typeof audience === 'string') return audience === oauthAudience;
  return Array.isArray(audience) && audience.includes(oauthAudience);
}

function validateStandardClaims(payload: {
  iss?: unknown;
  aud?: unknown;
  exp?: unknown;
  nbf?: unknown;
}): string | undefined {
  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== oauthIssuer) return 'Token issuer does not match';
  if (!audienceMatches(payload.aud)) return 'Token audience does not match this MCP resource';
  if (typeof payload.exp !== 'number' || payload.exp <= now) return 'Token is expired or missing exp';
  if (typeof payload.nbf === 'number' && payload.nbf > now) return 'Token is not active yet';
  return undefined;
}

function checkScopes(payload: { scope?: unknown; scp?: unknown }): AuthorizationResult {
  const scopes = tokenScopes(payload);
  const missingScopes = requiredScopes.filter((scope) => !scopes.has(scope));
  return missingScopes.length > 0
    ? { authorized: false, status: 403, missingScopes }
    : { authorized: true };
}

async function validateJwt(token: string): Promise<AuthorizationResult> {
  if (!jwks) return { authorized: false, status: 401, reason: 'invalid' };
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: oauthIssuer,
      audience: oauthAudience,
      requiredClaims: ['exp', 'iss', 'aud'],
    });
    return checkScopes(payload as JWTPayload);
  } catch (error) {
    return {
      authorized: false,
      status: 401,
      reason: 'invalid',
      description: error instanceof Error ? error.message : 'Invalid access token',
    };
  }
}

async function validateOpaqueToken(token: string): Promise<AuthorizationResult> {
  const headers = new Headers({ 'Content-Type': 'application/x-www-form-urlencoded' });
  if (introspectionClientId && introspectionClientSecret) {
    headers.set(
      'Authorization',
      `Basic ${Buffer.from(`${introspectionClientId}:${introspectionClientSecret}`).toString('base64')}`
    );
  }

  const response = await fetch(introspectionUrl!, {
    method: 'POST',
    headers,
    body: new URLSearchParams({ token, token_type_hint: 'access_token' }),
  });

  if (!response.ok) {
    return {
      authorized: false,
      status: 401,
      reason: 'invalid',
      description: `Token introspection failed with HTTP ${response.status}`,
    };
  }

  const payload = (await response.json()) as IntrospectionResponse;
  if (payload.active !== true) {
    return { authorized: false, status: 401, reason: 'invalid', description: 'Inactive token' };
  }

  const claimError = validateStandardClaims(payload);
  if (claimError) {
    return { authorized: false, status: 401, reason: 'invalid', description: claimError };
  }

  return checkScopes(payload);
}

async function authorize(req: IncomingMessage): Promise<AuthorizationResult> {
  if (authMode === 'api-key') {
    const credential = extractApiKey(req);
    if (!credential || !expectedDigest) {
      return { authorized: false, status: 401, reason: 'missing' };
    }
    return timingSafeEqual(expectedDigest, digest(credential))
      ? { authorized: true }
      : { authorized: false, status: 401, reason: 'invalid', description: 'Invalid API key' };
  }

  const token = extractBearerToken(req);
  if (!token) return { authorized: false, status: 401, reason: 'missing' };
  return tokenMode === 'jwt' ? validateJwt(token) : validateOpaqueToken(token);
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
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=300',
  });
  res.end(
    JSON.stringify({
      resource: resourceUrl!.toString().replace(/\/$/, ''),
      authorization_servers: [oauthIssuer],
      bearer_methods_supported: ['header'],
      ...(requiredScopes.length > 0 ? { scopes_supported: requiredScopes } : {}),
    })
  );
}

function isProtectedResourceMetadataPath(pathname: string): boolean {
  if (!resourceUrl) return false;
  const resourcePath = resourceUrl.pathname === '/' ? '' : resourceUrl.pathname.replace(/\/$/, '');
  return (
    pathname === '/.well-known/oauth-protected-resource' ||
    pathname === `/.well-known/oauth-protected-resource${resourcePath}`
  );
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, X-API-Key, Content-Type, MCP-Protocol-Version',
      'Access-Control-Expose-Headers': 'WWW-Authenticate',
      'Access-Control-Max-Age': '600',
    });
    res.end();
    return;
  }

  const requestUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  if (authMode === 'oauth' && isProtectedResourceMetadataPath(requestUrl.pathname)) {
    serveProtectedResourceMetadata(res);
    return;
  }

  let authResult: AuthorizationResult;
  try {
    authResult = await authorize(req);
  } catch (error) {
    console.error(
      `[auth-gateway] Authorization failure: ${error instanceof Error ? error.message : String(error)}`
    );
    authResult = {
      authorized: false,
      status: 401,
      reason: 'invalid',
      description: 'Unable to validate access token',
    };
  }

  if (!authResult.authorized) {
    if (authResult.status === 403) forbidden(res, authResult.missingScopes);
    else unauthorized(res, authResult.reason, authResult.description);
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
      responseHeaders['access-control-expose-headers'] = 'WWW-Authenticate';
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
    `[auth-gateway] mode=${authMode}${authMode === 'oauth' ? `/${tokenMode}` : ''} ` +
      `listening=http://${listenHost}:${listenPort} upstream=${upstreamUrl.toString()}`
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
