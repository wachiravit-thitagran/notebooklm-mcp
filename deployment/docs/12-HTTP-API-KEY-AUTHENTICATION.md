# HTTP API key authentication

> [!WARNING]
> AI Generated — review the deployment and network controls before using this in production.

The NotebookLM HTTP server should not be exposed directly to the public internet. Run the existing HTTP server on a private loopback port and place the authenticated gateway in front of it.

## Architecture

```text
Claude / MCP client
  -> Bearer API key
  -> authenticated gateway :3001
  -> private NotebookLM HTTP server 127.0.0.1:3000
```

## Generate a key

```bash
openssl rand -hex 32
```

Store the result in a secret manager or protected environment file. Do not commit it to Git.

## Start the private backend

Bind the HTTP server to loopback only:

```bash
HTTP_HOST=127.0.0.1 HTTP_PORT=3000 npm run start:http
```

## Start the authenticated gateway

```bash
MCP_API_KEY='<64-character-secret>' \
MCP_UPSTREAM_URL=http://127.0.0.1:3000 \
MCP_AUTH_HOST=0.0.0.0 \
MCP_AUTH_PORT=3001 \
npm run start:auth-gateway
```

Only port `3001` should be published through Docker, a reverse proxy, Cloudflare Tunnel, or a firewall. Port `3000` must remain private.

## Test authentication

Without a key:

```bash
curl -i http://server.example:3001/health
```

Expected result: `401 Unauthorized`.

With a Bearer token:

```bash
curl -i \
  -H "Authorization: Bearer $MCP_API_KEY" \
  http://server.example:3001/health
```

The gateway also accepts `X-API-Key`, but Bearer authentication is preferred.

## Claude Code client

```bash
claude mcp add notebooklm-secure --scope user \
  --env NOTEBOOKLM_SERVER_URL=https://server.example \
  --env MCP_API_KEY='<64-character-secret>' \
  -- npx -y --package @roomi-fields/notebooklm-mcp \
  notebooklm-mcp-secure-remote
```

The secure client injects `Authorization: Bearer <key>` into every HTTP request made by the existing stdio-to-HTTP proxy.

## Security notes

- Use HTTPS for any connection that leaves the local machine or trusted private network.
- Keep the upstream HTTP server bound to `127.0.0.1` or a private container network.
- Rotate API keys periodically and immediately after suspected disclosure.
- Restrict access with firewall rules, VPN, Cloudflare Access, or another identity-aware proxy when possible.
- The gateway intentionally returns a generic unauthorized response and does not expose key-validation details.
