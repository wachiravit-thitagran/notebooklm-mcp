# Remote HTTP authentication

> [!WARNING]
> AI Generated — review the deployment, identity-provider, and network controls before production use.

Do not expose the NotebookLM HTTP backend directly. Bind it to loopback or a private container network and publish only the authenticated gateway.

The gateway supports:

- `api-key`: static secret for simple private deployments
- `oauth`: MCP OAuth resource-server mode with either JWT/JWKS validation or RFC 7662 token introspection

## Architecture

```text
MCP client
  -> Authorization: Bearer <credential>
  -> authenticated gateway
  -> private NotebookLM HTTP backend
```

## Private backend

```bash
HTTP_HOST=127.0.0.1 HTTP_PORT=3000 npm run start:http
```

## API-key mode

```bash
MCP_AUTH_MODE=api-key \
MCP_API_KEY="$(openssl rand -hex 32)" \
MCP_UPSTREAM_URL=http://127.0.0.1:3000 \
MCP_AUTH_HOST=0.0.0.0 \
MCP_AUTH_PORT=3001 \
npm run start:auth-gateway
```

Clients may use either:

```http
Authorization: Bearer <api-key>
```

or:

```http
X-API-Key: <api-key>
```

API-key mode is not the MCP OAuth authorization protocol. It exists for clients that support custom headers but do not support interactive OAuth discovery.

## OAuth mode

OAuth mode makes the gateway an OAuth 2.1 protected resource. An external authorization server must provide authorization, token issuance, client registration or client metadata support, PKCE, and refresh-token behavior as required by the MCP client.

Common settings:

```bash
MCP_AUTH_MODE=oauth \
MCP_RESOURCE_URL=https://mcp.example.com/mcp \
MCP_OAUTH_ISSUER=https://auth.example.com \
MCP_OAUTH_AUDIENCE=https://mcp.example.com/mcp \
MCP_OAUTH_REQUIRED_SCOPES="notebooklm.read notebooklm.write" \
MCP_UPSTREAM_URL=http://127.0.0.1:3000 \
MCP_AUTH_HOST=0.0.0.0 \
MCP_AUTH_PORT=3001 \
npm run start:auth-gateway
```

`MCP_RESOURCE_URL` is the canonical protected-resource identifier and must match the resource/audience for which access tokens are issued.

### JWT access tokens

```bash
MCP_OAUTH_TOKEN_MODE=jwt \
MCP_OAUTH_JWKS_URL=https://auth.example.com/.well-known/jwks.json
```

JWT mode validates:

- signature through the provider JWKS
- `iss`
- `aud`
- required `exp`
- optional `nbf`
- required scopes from `scope` or `scp`

### Opaque access tokens

```bash
MCP_OAUTH_TOKEN_MODE=introspection \
MCP_OAUTH_INTROSPECTION_URL=https://auth.example.com/oauth2/introspect \
MCP_OAUTH_INTROSPECTION_CLIENT_ID=notebooklm-resource-server \
MCP_OAUTH_INTROSPECTION_CLIENT_SECRET='<secret>'
```

Introspection mode requires an active response and validates issuer, audience, expiry, not-before, and scopes. The authorization server must return those claims in the introspection response.

## MCP protected-resource discovery

For a resource URL such as:

```text
https://mcp.example.com/mcp
```

the gateway serves RFC 9728 metadata at:

```text
https://mcp.example.com/.well-known/oauth-protected-resource/mcp
```

It also serves the root compatibility location:

```text
https://mcp.example.com/.well-known/oauth-protected-resource
```

Example:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://auth.example.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["notebooklm.read", "notebooklm.write"]
}
```

## Authorization responses

Missing bearer token:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="notebooklm-mcp",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
  scope="notebooklm.read notebooklm.write"
```

Invalid or expired token adds:

```text
error="invalid_token"
```

A valid token without sufficient scope receives:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer
  error="insufficient_scope",
  scope="<missing-scopes>",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
```

The gateway removes `Authorization` and `X-API-Key` before forwarding the request to the private backend.

## Authorization-server requirements

For automatic MCP client login, the external authorization server must expose OAuth authorization-server or OpenID Connect discovery metadata and support the client-registration mechanism used by the chosen MCP host. The client is responsible for Authorization Code with PKCE, the `resource` parameter, token storage, and refresh-token use.

## Security requirements

- Use HTTPS for every non-local OAuth endpoint and MCP resource.
- Never expose the upstream NotebookLM backend publicly.
- Issue access tokens specifically for the MCP resource audience.
- Use short-lived access tokens and rotate signing keys safely.
- Keep introspection credentials and API keys in a secret manager.
- Do not pass upstream tokens through the MCP server to unrelated services.
