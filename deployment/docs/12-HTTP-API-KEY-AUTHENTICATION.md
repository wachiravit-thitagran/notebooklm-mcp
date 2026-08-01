# Remote HTTP authentication

> [!WARNING]
> AI Generated — review the deployment, identity-provider, and network controls before using this in production.

The NotebookLM HTTP server should not be exposed directly to the public internet. Run the existing HTTP server on a private loopback port and place the authenticated gateway in front of it.

The gateway supports two modes:

- `api-key`: simple self-hosted protection using a static secret
- `oauth`: OAuth 2.1 resource-server mode using bearer JWTs from an external OAuth/OIDC provider

## Architecture

```text
Claude / MCP client
  -> Bearer credential
  -> authenticated gateway :3001
  -> private NotebookLM HTTP server 127.0.0.1:3000
```

## Private backend

Bind the HTTP server to loopback only:

```bash
HTTP_HOST=127.0.0.1 HTTP_PORT=3000 npm run start:http
```

Only the authenticated gateway port should be published. Port `3000` must remain private.

## Mode 1: API key

Generate a key:

```bash
openssl rand -hex 32
```

Start the gateway:

```bash
MCP_AUTH_MODE=api-key \
MCP_API_KEY='<64-character-secret>' \
MCP_UPSTREAM_URL=http://127.0.0.1:3000 \
MCP_AUTH_HOST=0.0.0.0 \
MCP_AUTH_PORT=3001 \
npm run start:auth-gateway
```

Test it:

```bash
curl -i http://server.example:3001/health

curl -i \
  -H "Authorization: Bearer $MCP_API_KEY" \
  http://server.example:3001/health
```

The gateway also accepts `X-API-Key`, but Bearer authentication is preferred.

Claude Code client:

```bash
claude mcp add notebooklm-secure --scope user \
  --env NOTEBOOKLM_SERVER_URL=https://server.example \
  --env MCP_API_KEY='<64-character-secret>' \
  -- npx -y --package @roomi-fields/notebooklm-mcp \
  notebooklm-mcp-secure-remote
```

## Mode 2: OAuth resource server

OAuth mode does not implement an authorization server. Configure an external OAuth 2.1 or OIDC provider that issues signed JWT access tokens.

Required settings:

```bash
MCP_AUTH_MODE=oauth \
MCP_RESOURCE_URL=https://mcp.example.com \
MCP_OAUTH_ISSUER=https://auth.example.com \
MCP_OAUTH_AUDIENCE=https://mcp.example.com \
MCP_OAUTH_JWKS_URL=https://auth.example.com/.well-known/jwks.json \
MCP_OAUTH_REQUIRED_SCOPES='notebooklm.read notebooklm.write' \
MCP_UPSTREAM_URL=http://127.0.0.1:3000 \
MCP_AUTH_HOST=0.0.0.0 \
MCP_AUTH_PORT=3001 \
npm run start:auth-gateway
```

The gateway validates:

- JWT signature using the provider JWKS endpoint
- `iss` against `MCP_OAUTH_ISSUER`
- `aud` against `MCP_OAUTH_AUDIENCE`
- token expiry and not-before timestamps
- required scopes from either `scope` or `scp`

Protected Resource Metadata is available without authentication at:

```text
https://mcp.example.com/.well-known/oauth-protected-resource
```

Example response:

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["notebooklm.read", "notebooklm.write"]
}
```

Requests without a valid token receive `401` with a `WWW-Authenticate` challenge containing the protected-resource metadata URL. Valid tokens missing required scopes receive `403 insufficient_scope`.

OAuth-capable MCP clients should discover the authorization server and obtain access tokens themselves. Clients that already have a token can send:

```http
Authorization: Bearer <oauth-access-token>
```

## Security notes

- Use HTTPS for all non-local connections.
- Keep the upstream HTTP server bound to `127.0.0.1` or a private container network.
- Store API keys and OAuth configuration in a secret manager.
- Rotate API keys immediately after suspected disclosure.
- Configure short-lived OAuth access tokens and validate audience strictly.
- Restrict access further with firewall rules, VPN, Cloudflare Access, or another identity-aware proxy when appropriate.
- The gateway strips `Authorization` and `X-API-Key` before forwarding requests to the NotebookLM backend.
