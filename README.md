<!-- omit from toc -->
# Authsome MCP Proxy

A [Model Context Protocol](https://modelcontextprotocol.com) (MCP) proxy that
bridges *upstream MCP servers protected by token validation or static
credentials* to MCP clients such as Claude Desktop, Claude Code, Cursor,
Codex, MCP Inspector, and Claude.ai. ("Authsome" as in *awesome*, but with
auth.)

The proxy can run as:

- **Web connector** (`--transport http`, **recommended for end users**) —
  a persistent HTTP server that any MCP client reaches by URL. Downstream
  clients authenticate against the proxy via Dynamic Client Registration
  or a Client ID Metadata Document; the proxy bridges to your IdP and
  forwards traffic upstream. A single
  instance can serve many users simultaneously and lives behind a normal
  URL (`https://mcp.example.com/mcp`) — no per-user config files,
  subprocess launchers, or local Python toolchains. This is the default
  for non-developer rollouts and the only mode that works with web-only
  clients like Claude.ai.

- **Local stdio proxy** (`--transport stdio`, the default for backwards
  compatibility, **developer use**) — launched as a subprocess by the MCP
  client (Claude Desktop, Cursor, Codex, Claude Code via `claude mcp
  add --transport stdio`). Each user runs their own instance and the proxy
  performs the OAuth flow against an external OIDC IdP on their behalf.
  Useful when you don't have a server to host the proxy on or when the
  upstream MCP only validates tokens and you want each developer to
  authenticate locally.

- [What Is This For?](#what-is-this-for)
- [Prerequisites](#prerequisites)
- [Web Connector (Recommended)](#web-connector-recommended)
  - [How it works](#how-it-works)
  - [Keycloak](#keycloak)
  - [Generic OIDC](#generic-oidc)
  - [AWS Cognito](#aws-cognito)
  - [Google](#google)
  - [Azure (Entra ID)](#azure-entra-id)
  - [Connecting downstream MCP clients](#connecting-downstream-mcp-clients)
  - [Identity advertised to downstream clients](#identity-advertised-to-downstream-clients)
  - [Serving several hostnames from one deployment](#serving-several-hostnames-from-one-deployment)
  - [Serving several upstreams from one deployment](#serving-several-upstreams-from-one-deployment)
- [Local Stdio Proxy (Developer Use)](#local-stdio-proxy-developer-use)
  - [Claude Desktop / Cursor / Codex](#claude-desktop--cursor--codex)
  - [Claude Code](#claude-code)
  - [MCP Inspector](#mcp-inspector)
  - [Development from source](#development-from-source)
  - [Custom redirect port](#custom-redirect-port)
- [Advanced: Outbound Credential Substitution](#advanced-outbound-credential-substitution)
  - [When to use this](#when-to-use-this)
  - [`static` mode (API key, API token, PAT)](#static-mode-api-key-api-token-pat)
  - [`oauth-client-credentials` mode (service-account OAuth)](#oauth-client-credentials-mode-service-account-oauth)
  - [Caveats](#caveats)
- [Configuration Reference](#configuration-reference)
  - [Environment variables and CLI flags](#environment-variables-and-cli-flags)
- [Credential Management](#credential-management)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

# What Is This For?

Use `authsome-mcp-proxy` when you need to connect MCP clients to an upstream
MCP server that:

- Validates inbound bearer tokens against an external IdP but doesn't run
  its own OAuth authorization server, so MCP clients see no auth
  metadata and skip authentication entirely (resulting in `401
  Unauthorized` on every tool call); or

- Authenticates callers via static credentials (API keys, API tokens,
  personal access tokens, OAuth client_credentials) while your MCP client
  is web-based — Claude.ai, for example. Such clients accept only a
  connector URL in their config and expect the server they point at to
  be — or pretend to be — a standard OAuth/OIDC authorization server,
  which an upstream behind raw static credentials isn't. The proxy
  terminates OIDC inbound and injects the static credential outbound.

The proxy fills these gaps by:

1. **Inbound** — terminating the standard MCP auth handshake against an
   IdP the operator configures (Keycloak, OIDC, AWS Cognito, Google,
   Azure), so downstream MCP clients can perform Dynamic Client
   Registration and the OAuth code flow without modifying the upstream;
   and

2. **Outbound** — forwarding the user's session token to the upstream
   (the default; works when the upstream and the proxy validate against
   the same IdP), or substituting a configured static header /
   service-account token if the upstream uses a separate credential
   mechanism. See [Advanced: Outbound Credential Substitution](#advanced-outbound-credential-substitution)
   for the latter case.

The proxy presupposes the upstream is itself an *MCP-native* server (one
that exposes the MCP protocol — typically a web connector backed by a
REST API in the same codebase). If your upstream is a bare REST API
without MCP, build a full FastMCP server with `@mcp.tool()`-decorated
handlers instead — this proxy can't synthesize tool definitions for you.

# Prerequisites

This tool requires `uvx` (part of [uv](https://docs.astral.sh/uv/)). Install it via:

```bash
# Windows
winget install --id=astral-sh.uv -e

# macOS
brew install uv

# Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

> [!IMPORTANT]
> **macOS:** the `curl` installer places `uv` in `~/.local/bin/` and
> updates your shell profile, but macOS GUI apps like Claude Desktop do
> not load shell startup files — Claude Desktop won't find `uv` even
> though it works in your terminal. Installing via Homebrew avoids this
> entirely (it places `uv` in `/opt/homebrew/bin/` on Apple Silicon or
> `/usr/local/bin/` on Intel — paths GUI apps can see). If you already
> installed `uv` via `curl`, either reinstall with `brew install uv` or
> symlink it: `sudo ln -s ~/.local/bin/uv /usr/local/bin/uv`.

See the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/) for more options.

# Web Connector (Recommended)

Run the proxy as a persistent HTTP server. Downstream MCP clients connect
by URL (e.g. `https://mcp.example.com/mcp`). A single instance serves
many users concurrently; each MCP session gets an isolated upstream
connection so users never see each other's traffic.

## How it works

```
Browser           MCP Client (Claude.ai/Code/Inspector)
   │                       │
   │  OAuth login          │  1. DCR + auth-code + token
   │ ◄────────────────────►│ ◄──────────────────────────────┐
   │                       │                                │
   │                       │  2. tools, prompts, resources  │
   │                       │     (Authorization: Bearer X)  │
   │                       ▼                                │
   │            ┌─────────────────────┐                     │
   │            │  authsome-mcp-proxy │                     │
   │            │  --transport http   │                     │
   │            └─────────────────────┘                     │
   │                       │                                │
   │                       │  3. Authorization: Bearer X    │
   │                       ▼   (forwarded)                  │
   │            ┌─────────────────────┐                     │
   │            │   Upstream MCP      │                     │
   │            │   server            │                     │
   │            └─────────────────────┘                     │
   │                                                        │
   └─── Same IdP issues tokens both sides validate ─────────┘
```

The proxy wears two OAuth 2.0 hats at the same time: it is an **OAuth 2.0
client** against the upstream IdP / Authorization Server, and a
**OAuth 2.0 Authorization Server** for the MCP client, which may identify
itself either by Dynamic Client Registration or by
[CIMD](#client-id-metadata-documents-cimd) URL. The
only way it diverges from a stock AS is that it does not mint its own
tokens — it forwards the upstream IdP's tokens through transparently,
which is what makes `OUTBOUND_AUTH=forward` work end-to-end. For the full
sequence diagram, persistence model, and pod-restart implications, see
[docs/oauth-flow.md](docs/oauth-flow.md).

The proxy is IdP-agnostic — pick the inbound provider that matches your
deployment via `--inbound-auth-provider`. The following sections give a
working example for each.

> [!IMPORTANT]
> All examples below assume the upstream MCP server validates tokens
> against the *same* IdP that fronts the proxy (`--outbound-auth forward`,
> the default). If the upstream uses a separate credential mechanism (API
> key, service-account token, etc.), see [Advanced: Outbound Credential Substitution](#advanced-outbound-credential-substitution).

## Keycloak

For modern Keycloak (≥ 26.6.0) the proxy uses
[`KeycloakAuthProvider`](https://github.com/jlowin/fastmcp/blob/main/src/fastmcp/server/auth/providers/keycloak.py),
a `RemoteAuthProvider`. Keycloak supports MCP-compatible Dynamic Client
Registration natively, so the proxy holds **no IdP credentials of its
own** — downstream MCP clients DCR directly against Keycloak. The proxy's
job reduces to JWT verification + protected-resource metadata
advertising.

```bash
uvx authsome-mcp-proxy \
  --transport http \
  --port 8000 \
  --proxy-base-url https://mcp.example.com \
  --inbound-auth-provider keycloak \
  --oidc-issuer-url https://keycloak.example.com/realms/myrealm \
  --oidc-scopes "openid email" \
  --audience mcp-server \
  https://mcp-upstream.example.com/mcp
```

For Keycloak < 26.6.0, use [`--inbound-auth-provider oidc`](#generic-oidc)
instead — older Keycloak versions don't support MCP-compatible DCR
natively, so the DCR-bridge mode of `OIDCProxy` is required.

## Generic OIDC

Use this for any OIDC-compliant IdP that *doesn't* support MCP-compatible
DCR natively (older Keycloak, Auth0, Okta, etc.). The proxy itself
holds a pre-registered static client with the IdP and bridges downstream
DCR requests to the IdP's static-client model.

```bash
uvx authsome-mcp-proxy \
  --transport http \
  --port 8000 \
  --proxy-base-url https://mcp.example.com \
  --inbound-auth-provider oidc \
  --oidc-issuer-url https://idp.example.com \
  --oidc-client-id mcp-proxy-client \
  --oidc-client-secret <secret> \
  --oidc-scopes "openid email profile" \
  --audience mcp-server \
  https://mcp-upstream.example.com/mcp
```

The OIDC discovery URL is derived as
`{oidc-issuer-url}/.well-known/openid-configuration`. Register the
proxy's `{proxy-base-url}/auth/callback` as an allowed redirect URI in
your IdP's client config.

## AWS Cognito

```bash
uvx authsome-mcp-proxy \
  --transport http \
  --port 8000 \
  --proxy-base-url https://mcp.example.com \
  --inbound-auth-provider aws-cognito \
  --cognito-user-pool-id eu-central-1_XXXXXXXXX \
  --cognito-aws-region eu-central-1 \
  --oidc-client-id <cognito-app-client-id> \
  --oidc-client-secret <cognito-app-client-secret> \
  --oidc-scopes openid \
  https://mcp-upstream.example.com/mcp
```

Cognito requires a **confidential app client** (one with "Generate a
client secret" enabled) — FastMCP's `AWSCognitoProvider` mandates a
client_secret. Register `{proxy-base-url}/auth/callback` as an allowed
callback URL in the app client configuration. Cognito issues refresh
tokens automatically when "Authorization code grant" is enabled — no
`offline_access` scope needed.

## Google

```bash
uvx authsome-mcp-proxy \
  --transport http \
  --port 8000 \
  --proxy-base-url https://mcp.example.com \
  --inbound-auth-provider google \
  --oidc-client-id <google-oauth-client-id>.apps.googleusercontent.com \
  --oidc-client-secret <google-oauth-client-secret> \
  --oidc-scopes "openid email profile" \
  https://mcp-upstream.example.com/mcp
```

Create the OAuth client via the [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
Add `{proxy-base-url}/auth/callback` to the client's authorized redirect
URIs.

## Azure (Entra ID)

```bash
uvx authsome-mcp-proxy \
  --transport http \
  --port 8000 \
  --proxy-base-url https://mcp.example.com \
  --inbound-auth-provider azure \
  --azure-tenant-id <tenant-uuid> \
  --azure-identifier-uri "api://mcp-server" \
  --oidc-client-id <azure-app-client-id> \
  --oidc-client-secret <azure-app-client-secret> \
  --oidc-scopes "User.Read" \
  https://mcp-upstream.example.com/mcp
```

Azure has two specifics worth knowing: `--oidc-scopes` are taken literally
and prefixed with `--azure-identifier-uri` automatically before being sent
to Azure (`api://mcp-server/User.Read`), and the tenant ID is required
because the issuer URL embeds it.

## Connecting downstream MCP clients

Once the proxy is running on `https://mcp.example.com:8000/mcp`:

**Claude.ai:** in *Settings → Connectors → Add custom connector*, paste
the URL. Claude will perform DCR against the proxy and walk the user
through the OAuth flow in the browser.

**Claude Code:**
```bash
claude mcp add --transport http my-server https://mcp.example.com:8000/mcp
```

**MCP Inspector:**
```bash
npx -y @modelcontextprotocol/inspector
```
…then in the UI: set *Transport Type* to **Streamable HTTP**, paste
`https://mcp.example.com:8000/mcp` into *URL*, and — importantly — set
*Connection Type* to **Via Proxy** (the default *Direct* mode bypasses
Inspector's local OAuth helper and breaks the authorization flow against
the proxy). Then click *Connect*.

> [!NOTE]
> On headless hosts (Docker, cloud VM, CI), the web connector doesn't
> need a browser on the proxy machine — downstream MCP clients drive the
> OAuth browser flow from wherever the user is sitting. Just expose the
> proxy at a reachable URL and you're done.

## Client ID Metadata Documents (CIMD)

DCR isn't the only way a downstream client can identify itself. With
[Client ID Metadata Documents][cimd-draft] (adopted into MCP as SEP-991)
a client hosts a small JSON document at an HTTPS URL it controls, and
that URL *is* its `client_id`. The proxy fetches the document on first
use instead of handing out a freshly registered client.

Two things follow from that. The client keeps one durable identity
across every server it talks to, rather than a different `client_id` per
proxy instance. And because the metadata lives at the client's own URL,
the proxy can re-fetch it after a restart — where a DCR registration
that lived only in the proxy's client store is simply gone.

CIMD is **enabled by default** and is purely additive: DCR keeps working
exactly as before, so nothing changes for clients that don't use CIMD.
Turn it off with `--no-enable-cimd` (or `ENABLE_CIMD=false`).

Support depends on the inbound provider, because it depends on who is
acting as the authorization server:

| `--inbound-auth-provider` | CIMD |
|---|---|
| `oidc`, `google`, `azure`, `aws-cognito` | ✅ the proxy is the authorization server, and handles CIMD itself |
| `keycloak` | ⚠️ not the proxy's call — clients register directly with Keycloak, so CIMD works only if your Keycloak does. `ENABLE_CIMD` is inert here. |

> [!IMPORTANT]
> The proxy fetches the document from the client's own domain, so it
> needs outbound HTTPS to the public internet. A deployment whose egress
> is locked down to the IdP only will reject every CIMD client while DCR
> keeps working — a confusing failure worth ruling out first. The fetch
> is SSRF-hardened by FastMCP (HTTPS only, public IPs only, no
> redirects, 5 KB cap), so it cannot be pointed at internal addresses.

To try it, generate and check a document with FastMCP's CLI:

```bash
uvx fastmcp cimd create --name "My Client" -r "http://localhost:*/callback"
# host the result at e.g. https://client.example.com/oauth/client.json
uvx fastmcp cimd validate https://client.example.com/oauth/client.json
```

…then connect with that URL as the client id. A successful CIMD
connection reaches `/authorize` with no `/register` call ahead of it.

[cimd-draft]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document

## Identity advertised to downstream clients

In stdio mode the proxy relays the upstream MCP server's identity (name,
version, instructions, website URL, icons) at startup, so the proxy
appears transparent.

In web mode the proxy cannot read the upstream at startup: with
`--outbound-auth forward` the upstream only accepts a user's token, and
no user has connected yet. So the identity is split:

- **Instructions, website URL and icons** are relayed from the upstream
  when a client connects. The first handshake fetches them with that
  client's credential; the result is cached for 10 minutes, so a
  redeployed upstream is picked up without restarting the proxy. If the
  fetch fails, the client still connects and sees the proxy's own values.
- **Name and version** are yours to set. FastMCP also uses the server
  name outside the handshake, where a relayed value would not reach it.
  Unset, they fall back to FastMCP's auto-generated `FastMCPProxy-xxxx`
  and FastMCP's own version.

Any field you set explicitly wins over the relayed one:

```bash
uvx authsome-mcp-proxy ... \
  --proxy-name "Awesome tool" \
  --proxy-version 1.2.3 \
  --proxy-instructions "Use this tool to do amazing things." \
  --proxy-website-url https://awesome.tool.example.com
```

## Serving several hostnames from one deployment

Sometimes the same proxy has to be reachable under more than one public
hostname — an alias domain for customers whose networks block your
primary TLD, a vanity host, or both names running side by side during a
migration. Pass them as a comma-separated list:

```bash
uvx authsome-mcp-proxy ...   --proxy-base-url https://mcp.example.io,https://mcp.example.com
```

The first entry is **canonical**: it is the identity served to requests
that arrive with no `Host` header or an unrecognized one, which is what
container health probes addressing the pod IP do.

Each hostname is served as a *fully separate OAuth identity* — its own
protected-resource metadata, its own authorization-server metadata, its
own `redirect_uri`. A client that reaches `mcp.example.com` is never
handed `mcp.example.io` to continue its flow with, which is the entire
point when the alias exists because the primary domain is unreachable.

You will need to **register `{base_url}/auth/callback` for every entry**
as an allowed redirect URI with your IdP. Two entries sharing a hostname
(differing only in scheme, port or path) are rejected at startup, since
the `Host` header cannot tell them apart.

> [!NOTE]
> This cannot be solved at the load balancer. Adding a second host to the
> ingress fixes TLS and routing, but a FastMCP auth provider bakes its
> `base_url` in at construction and advertises it everywhere, so the proxy
> keeps answering discovery with the first hostname. Rewriting the
> hostname in responses at the edge fails too: it survives the metadata
> documents and the redirect, then breaks at the server-to-server token
> exchange, where `redirect_uri` must byte-match what the IdP saw earlier.
> The proxy therefore builds one app per hostname over one shared server
> and dispatches on `Host` — a duplicated front door, not a duplicated
> backend.

## Serving several upstreams from one deployment

One proxy can also front several upstream MCP servers, each under its own
path, behind a single sign-in — a repository server that validates the
user's token next to a read-only knowledge base that validates nothing,
say. Name the upstreams in `UPSTREAMS` instead of setting
`UPSTREAM_MCP_URL`, and give each one its URL:

```bash
UPSTREAMS=secure,emb3d
UPSTREAM_SECURE_MCP_URL=http://secure-repository:8080/mcp
UPSTREAM_EMB3D_MCP_URL=http://emb3d:8080/mcp
UPSTREAM_EMB3D_OUTBOUND_AUTH=none
UPSTREAM_EMB3D_PROXY_NAME="MITRE EMB3D"
DEFAULT_UPSTREAM=secure
```

On the command line, the routes themselves can be given as flags — the
per-upstream settings exist only as environment variables:

```bash
uvx authsome-mcp-proxy ... \
  --upstream secure=http://secure-repository:8080/mcp \
  --upstream emb3d=http://emb3d:8080/mcp \
  --default-upstream secure
```

Each upstream `NAME` is served at `{base_url}/NAME/mcp` — that is the URL
clients connect to — with its protected-resource metadata at
`{base_url}/.well-known/oauth-protected-resource/NAME/mcp`. Names are
lower-case letters, digits and `-`; in variable names they are upper-cased
with `-` turned into `_`, so `knowledge-base` reads
`UPSTREAM_KNOWLEDGE_BASE_MCP_URL`.

**Per upstream** are the URL, the outbound auth
(`UPSTREAM_<NAME>_OUTBOUND_*`), the identity advertised to clients
(`UPSTREAM_<NAME>_PROXY_*`) and the MCP sessions: a session opened on one
path is unknown on every other. Each `UPSTREAM_<NAME>_*` setting is
optional and falls back to its global counterpart — `OUTBOUND_AUTH`,
`OUTBOUND_HEADER_VALUE`, `MCP_PROXY_NAME` and so on — so settings common to
all upstreams are written once.

**Shared** is the OAuth identity: one IdP client, one
`{base_url}/auth/callback` to register, one `/authorize`, `/token` and
`/register`, and one authorization-server metadata document at the root. A
user who signs in while connecting to one upstream is signed in for all of
them — a token issued for `/secure/mcp` is accepted at `/emb3d/mcp` on the
same hostname.

`OUTBOUND_AUTH=none` (globally, or per upstream as above) sends the upstream
no credential at all. The user's token is not merely left out but removed:
the proxy otherwise passes the downstream request's `Authorization` header
along, and an upstream that authenticates nobody has no business seeing a
token that is valid for its neighbours.

`DEFAULT_UPSTREAM` additionally serves that upstream at the familiar `/mcp`
with its metadata at `/.well-known/oauth-protected-resource/mcp`. To turn a
single-upstream deployment into a multi-upstream one, move
`UPSTREAM_MCP_URL` to `UPSTREAM_<NAME>_MCP_URL`, list `NAME` in `UPSTREAMS`
and set `DEFAULT_UPSTREAM=NAME`: existing clients keep their URL. With the
`oidc`, `aws-cognito`, `google` and `azure` providers they sign in once more
after the switch, because the proxy now binds the tokens it issues to the
whole hostname rather than to `/mcp`.

Upstreams are connected per client session, never at startup, so the proxy
starts and serves every route while one upstream is down; only requests to
that upstream fail. `UPSTREAMS` and `UPSTREAM_MCP_URL` are mutually
exclusive, and several upstreams need `--transport http`. Combined with
[several hostnames](#serving-several-hostnames-from-one-deployment), every
hostname is its own identity serving every upstream.

> [!NOTE]
> Running one proxy per upstream behind a path-routing ingress does not
> get you here. Each instance would be a separate OAuth identity with its
> own IdP callback, and each would need the same root-level
> `/.well-known/oauth-authorization-server`, `/authorize` and `/token` —
> paths an ingress can send to only one of them. The proxy instead builds
> one app per upstream over one auth provider per hostname and dispatches
> on the path, so the authorization server and all of its state exist once.

# Local Stdio Proxy (Developer Use)

The original mode — the proxy is launched as a subprocess by the MCP
client, performs the OAuth flow against an external OIDC IdP on the
developer's behalf, caches tokens locally, and forwards them upstream.

Use stdio when:

- You don't have a server to host the proxy on.
- You're a developer who wants per-user authentication on their own
  machine rather than relying on a shared web deployment.
- The upstream is a token-validating MCP server that issues no OAuth
  metadata of its own, and your MCP client (Claude Desktop, etc.)
  therefore needs a local OAuth proxy to authenticate against the IdP on
  its behalf.

## Claude Desktop / Cursor / Codex

Add to your Claude Desktop config (accessible via *Settings → Developer →
Edit Config*). Cursor and Codex use the same JSON format in their
respective MCP settings files.

```jsonc
{
  "mcpServers": {
    "company-tools": {
      "command": "uvx",
      "args": [
        "authsome-mcp-proxy",
        "https://mcp-upstream.company.com/mcp"
      ],
      "env": {
        "OIDC_ISSUER_URL": "https://auth.company.com",
        "OIDC_CLIENT_ID": "claude-desktop-client",
        "OIDC_CLIENT_SECRET": "your-client-secret", // omit for public OIDC clients that don't require one
        "OIDC_SCOPES": "openid profile mcp:read mcp:write"
      }
    }
  }
}
```

> [!IMPORTANT]
> Configure `http://localhost:8080/auth/callback` (or whatever
> `OIDC_REDIRECT_URL` you set) as an allowed redirect URI in your OIDC
> client. Mismatched redirect URIs are the most common OAuth failure mode.

Restart the client to apply changes. On first connection the proxy opens
your browser for OIDC login; subsequent runs use the cached token.

To always use the latest version from PyPI (auto-updates), pin
`authsome-mcp-proxy@latest`:

```jsonc
"args": ["authsome-mcp-proxy@latest", "https://mcp-upstream.company.com/mcp"]
```

## Claude Code

```bash
claude mcp add --transport stdio my-server -- \
  uvx authsome-mcp-proxy \
  --oidc-issuer-url https://auth.example.com \
  --oidc-client-id my-client-id \
  https://mcp-upstream.example.com/mcp
```

Defaults to project scope (stored in `.mcp.json`). Add `--scope user` to
make the server available across all your projects.

## MCP Inspector

Create an `mcp.json`:

```jsonc
{
  "mcpServers": {
    "authsome-mcp-proxy": {
      "command": "uvx",
      "args": ["authsome-mcp-proxy", "https://mcp.example.com/mcp"],
      "env": {
        "OIDC_ISSUER_URL": "https://auth.example.com",
        "OIDC_CLIENT_ID": "inspector-client",
        "OIDC_CLIENT_SECRET": "your-client-secret" // omit for public OIDC clients that don't require one
      }
    }
  }
}
```

Then launch:

```bash
npx -y @modelcontextprotocol/inspector --config mcp.json --server authsome-mcp-proxy
```

## Development from source

When developing or testing local changes:

```jsonc
{
  "mcpServers": {
    "local-dev": {
      "command": "uv",
      "args": [
        "run",
        "--with-editable",
        "/path/to/authsome-mcp-proxy",
        "authsome-mcp-proxy",
        "https://mcp.example.com/mcp"
      ],
      "env": {
        "OIDC_ISSUER_URL": "https://auth.example.com",
        "OIDC_CLIENT_ID": "dev-client",
        "OIDC_CLIENT_SECRET": "your-client-secret" // omit for public OIDC clients that don't require one
      }
    }
  }
}
```

## Custom redirect port

If port 8080 is already in use, override the OAuth callback URL:

```jsonc
"env": {
  "OIDC_ISSUER_URL": "https://auth.example.com",
  "OIDC_CLIENT_ID": "my-client-id",
  "OIDC_CLIENT_SECRET": "your-client-secret", // omit for public OIDC clients that don't require one
  "OIDC_REDIRECT_URL": "http://localhost:9090/auth/callback"
}
```

…and add the chosen URL to your OIDC client's allowed redirect URIs.

# Advanced: Outbound Credential Substitution

For upstream MCP servers that *don't* validate tokens against the same
IdP that fronts the proxy. Two outbound mechanisms are supported, both
configured via `--outbound-auth`. These cover single-tenant deployments
where the upstream uses a tenant-wide service-account token or a per-user
API key / API token; full multi-user identity-bridging with per-user
credential storage is out of scope (see [Caveats](#caveats)).

## When to use this

You need outbound credential substitution if the upstream MCP server
authenticates the caller via something other than a bearer token from
your inbound IdP — for example a tenant-wide service-account token, a
per-user API key (CoinDesk-style), or a flat API key (Lexware-style).

If the proxy and upstream share the same IdP, *don't use this* — the
default `--outbound-auth forward` is what you want.

## `static` mode (API key, API token, PAT)

Injects a literal header value on every outbound request. Use this when
the upstream wants a fixed API key, API token, or PAT regardless of who
the calling user is.

```bash
uvx authsome-mcp-proxy \
  --transport http \
  --port 8000 \
  --proxy-base-url https://mcp.example.com \
  --inbound-auth-provider keycloak \
  --oidc-issuer-url https://kc.example.com/realms/r \
  --outbound-auth static \
  --outbound-header-name Authorization \
  --outbound-header-value "Bearer ${UPSTREAM_API_KEY}" \
  https://mcp-upstream.example.com/mcp
```

For upstreams that take the key in a non-Authorization header:

```bash
  --outbound-header-name X-API-Key \
  --outbound-header-value "${UPSTREAM_API_KEY}" \
```

The scope of the credential you paste in determines the effective
behaviour: a **tenant-wide** key terminates identity at the proxy (every
user looks the same to the upstream), while a **per-user** key bridges
that single user's identity through to the upstream (single-user
instance).

Common shapes:

- **Personio-style** tenant-scoped credentials (one shared service-account
  key for the whole org)
- **Lexware-style** flat tenant API key (no per-user identity at the
  upstream)
- **CoinDesk-style** per-user API token (the proxy holds the user's
  individual key)
- **GitLab / GitHub PATs** (per-user; same shape as CoinDesk)

## `oauth-client-credentials` mode (service-account OAuth)

Proxy obtains its own access token via the OAuth 2.0
client_credentials grant against an outbound token endpoint that is
*independent of the inbound IdP*. The token is cached and refreshed
on expiry.

```bash
uvx authsome-mcp-proxy \
  --transport http \
  --port 8000 \
  --proxy-base-url https://mcp.example.com \
  --inbound-auth-provider keycloak \
  --oidc-issuer-url https://kc.example.com/realms/r \
  --outbound-auth oauth-client-credentials \
  --outbound-token-url https://upstream-idp.example.com/oauth/token \
  --outbound-client-id "${UPSTREAM_SVC_CLIENT_ID}" \
  --outbound-client-secret "${UPSTREAM_SVC_CLIENT_SECRET}" \
  https://mcp-upstream.example.com/mcp
```

Equivalent to *static* with a tenant-scoped credential conceptually, but
the token is short-lived and refreshed automatically — preferred over a
flat shared API key when the upstream supports it.

## Caveats

- **Single-tenant only.** Identity is terminated at the proxy in
  tenant-scoped configurations — no ACL is enforced by the proxy itself,
  and every upstream call is indistinguishable to the upstream from any
  other authenticated user's. Tenant-scoped policy enforcement needs a
  separate PEP layer on top (the planned `fastmcp-edge-authz`);
  multi-user deployments with per-user credentials need a credential
  vault (the planned `fastmcp-edge-byok`).
- **The proxy presupposes the upstream is itself an MCP server.** For a
  bare REST API, embed MCP tools directly into the API codebase (Spring
  AI MCP Server Boot Starter, Quarkus MCP Server, official Node/Python
  SDKs, etc.) rather than fronting it with this proxy. The proxy can't
  synthesize tool definitions from a REST API.

# Configuration Reference

All options can be set via CLI flags or matching environment variables
(CLI wins). The full list:

## Environment variables and CLI flags

**Upstream coordinates** — either a single upstream or several (http mode):

| Env var | CLI flag | Description |
|---|---|---|
| `UPSTREAM_MCP_URL` | (positional) | URL of the upstream MCP server, served at `/mcp`. |
| `UPSTREAMS` | `--upstream NAME=URL` (repeatable) | Comma-separated names of several upstreams, each served at `/NAME/mcp` — see [Serving several upstreams from one deployment](#serving-several-upstreams-from-one-deployment). Mutually exclusive with `UPSTREAM_MCP_URL`. |
| `UPSTREAM_<NAME>_MCP_URL` | (the `URL` of `--upstream`) | URL of upstream `NAME`. |
| `DEFAULT_UPSTREAM` | `--default-upstream NAME` | Upstream additionally served at `/mcp`, for clients of a former single-upstream deployment. |

**Per-upstream settings** (environment only, with `UPSTREAMS`) — each
optional, falling back to its global counterpart:

| Env var | Falls back to |
|---|---|
| `UPSTREAM_<NAME>_OUTBOUND_AUTH` | `OUTBOUND_AUTH` |
| `UPSTREAM_<NAME>_OUTBOUND_HEADER_NAME` | `OUTBOUND_HEADER_NAME` |
| `UPSTREAM_<NAME>_OUTBOUND_HEADER_VALUE` | `OUTBOUND_HEADER_VALUE` |
| `UPSTREAM_<NAME>_OUTBOUND_CLIENT_ID` | `OUTBOUND_CLIENT_ID` |
| `UPSTREAM_<NAME>_OUTBOUND_CLIENT_SECRET` | `OUTBOUND_CLIENT_SECRET` |
| `UPSTREAM_<NAME>_OUTBOUND_TOKEN_URL` | `OUTBOUND_TOKEN_URL` |
| `UPSTREAM_<NAME>_PROXY_NAME` | `MCP_PROXY_NAME` |
| `UPSTREAM_<NAME>_PROXY_VERSION` | `MCP_PROXY_VERSION` |
| `UPSTREAM_<NAME>_PROXY_INSTRUCTIONS` | `MCP_PROXY_INSTRUCTIONS` |
| `UPSTREAM_<NAME>_PROXY_WEBSITE_URL` | `MCP_PROXY_WEBSITE_URL` |

**Proxy runtime** — all optional:

| Env var | CLI flag | Default | Description |
|---|---|---|---|
| `MCP_PROXY_TRANSPORT` | `--transport {stdio,http}` | `stdio` | Which transport to serve on. |
| `MCP_PROXY_HOST` | `--host` | `0.0.0.0` | HTTP-mode bind address. |
| `MCP_PROXY_PORT` | `--port` | `8000` | HTTP-mode listen port. |
| `MCP_PROXY_BASE_URL` | `--proxy-base-url` | _required for http_ | Publicly reachable URL of the proxy. Used to advertise auth metadata to downstream clients. Accepts a comma-separated list to serve several hostnames, each as its own OAuth identity — see [Serving several hostnames from one deployment](#serving-several-hostnames-from-one-deployment). |
| `MCP_PROXY_DEBUG` | `--debug` | _off_ | Enable debug logging. |

**Server identity advertised to downstream clients** (http mode):

| Env var | CLI flag | Description |
|---|---|---|
| `MCP_PROXY_NAME` | `--proxy-name` | Display name (e.g. `"itemis ANALYZE"`). |
| `MCP_PROXY_VERSION` | `--proxy-version` | Display version. |
| `MCP_PROXY_INSTRUCTIONS` | `--proxy-instructions` | Tool-selection hints for the LLM. |
| `MCP_PROXY_WEBSITE_URL` | `--proxy-website-url` | Project URL shown in client UIs. |

**Inbound auth** (http mode — pick a provider, then supply the fields it
needs):

| Env var | CLI flag | Description |
|---|---|---|
| `INBOUND_AUTH_PROVIDER` | `--inbound-auth-provider {oidc,keycloak,aws-cognito,google,azure}` | Which provider class to use. |
| `OIDC_ISSUER_URL` | `--oidc-issuer-url` | OIDC issuer / Keycloak realm URL. |
| `OIDC_CLIENT_ID` | `--oidc-client-id` | OAuth client ID at the IdP. |
| `OIDC_CLIENT_SECRET` | `--oidc-client-secret` | OAuth client secret (required for `aws-cognito`; optional for `oidc`/`google`/`azure`; unused for `keycloak`). |
| `OIDC_SCOPES` | `--oidc-scopes` | Space-separated scopes. |
| `AUDIENCE` | `--audience` | JWT `aud` claim to require (oidc/keycloak; recommended for production). |
| `COGNITO_USER_POOL_ID` | `--cognito-user-pool-id` | AWS Cognito user pool ID. |
| `COGNITO_AWS_REGION` | `--cognito-aws-region` | AWS region for the Cognito user pool. |
| `AZURE_TENANT_ID` | `--azure-tenant-id` | Azure AD tenant ID. |
| `AZURE_IDENTIFIER_URI` | `--azure-identifier-uri` | Azure Application ID URI used for scope prefixing. |
| `ENABLE_CIMD` | `--enable-cimd` / `--no-enable-cimd` | Accept Client ID Metadata Documents from downstream clients. On by default — see [Client ID Metadata Documents (CIMD)](#client-id-metadata-documents-cimd). |

**Outbound auth** (http mode — `forward` is the default and needs no
extra fields):

| Env var | CLI flag | Description |
|---|---|---|
| `OUTBOUND_AUTH` | `--outbound-auth {forward,none,oauth-client-credentials,static}` | Outbound mechanism. `none` sends the upstream no credential: the user's token is removed from the headers the proxy forwards. Other headers the client sends, such as `X-Api-Key`, still pass through in every mode, as before. |
| `OUTBOUND_TOKEN_URL` | `--outbound-token-url` | Token endpoint for `oauth-client-credentials`. |
| `OUTBOUND_CLIENT_ID` | `--outbound-client-id` | Client ID for `oauth-client-credentials`. |
| `OUTBOUND_CLIENT_SECRET` | `--outbound-client-secret` | Client secret for `oauth-client-credentials`. |
| `OUTBOUND_HEADER_NAME` | `--outbound-header-name` | Header name for `static` (default `Authorization`). |
| `OUTBOUND_HEADER_VALUE` | `--outbound-header-value` | Literal header value for `static`. |

**Inbound (stdio mode)** — only `OIDC_*` apply; transport and inbound
auth are not exposed downstream since the MCP client launches the proxy
as a trusted subprocess:

| Env var | CLI flag | Default | Description |
|---|---|---|---|
| `OIDC_REDIRECT_URL` | `--oidc-redirect-url` | `http://localhost:8080/auth/callback` | Local OAuth callback URL. |

Run `uvx authsome-mcp-proxy --help` for the always-current list.

# Credential Management

Tokens obtained in **stdio mode** (the proxy's OAuth code flow) are
cached in `~/.cache/authsome-mcp-proxy-<version>/` (where `<version>`
is the installed package version) as a SQLite database:

```
~/.cache/authsome-mcp-proxy-0.5.0/
  ├── cache.db
  ├── cache.db-shm
  └── cache.db-wal
```

To force re-authentication (switching accounts, expired tokens, etc.):

```bash
# Linux / macOS
rm -rf ~/.cache/authsome-mcp-proxy*

# Windows
rmdir /s %USERPROFILE%\.cache\authsome-mcp-proxy*
```

In **web mode** the proxy doesn't cache its own tokens — downstream MCP
clients each hold their own session token they obtained via DCR against
the proxy. Each client manages its own cache.

**Headless stdio first-run**: if your stdio deployment target has no
browser (Docker, headless VM, CI), authenticate once on a machine with a
browser to populate the cache, then copy it over:

```bash
# Linux / macOS
scp -r ~/.cache/authsome-mcp-proxy-<version> user@server:~/.cache/
```

Refresh tokens keep the cache valid for as long as the IdP allows. Add
`offline_access` to `OIDC_SCOPES` for Keycloak / Auth0 / Okta to get
long-lived refresh tokens; Cognito issues them automatically.

# Troubleshooting

**Browser doesn't open (stdio mode)** — check that port 8080 (or your
custom redirect port) isn't blocked, manually open the URL shown in the
proxy logs, and verify your firewall isn't blocking localhost
connections.

**`401 Unauthorized` from the upstream** — verify `OIDC_ISSUER_URL`
matches the IdP your upstream validates against, check requested scopes,
and clear the cache (`rm -rf ~/.cache/authsome-mcp-proxy*`) before
retrying. Run with `--debug` for token-level diagnostics.

**`redirect_uri mismatch` from the IdP** — add the proxy's callback URL
to the OAuth client's allowed redirect URIs at the IdP. For stdio mode
that's `http://localhost:8080/auth/callback` (or whatever
`OIDC_REDIRECT_URL` is set to); for web mode it's
`{MCP_PROXY_BASE_URL}/auth/callback`. The match has to be exact, including
trailing slashes. When `MCP_PROXY_BASE_URL` lists several hostnames, *each*
one needs its own callback registered — a hostname whose callback is missing
fails only at the end of the flow, after the user has already logged in.

**A client rejects a route's metadata, or reports a resource mismatch**
— with several upstreams, connect to the route's own URL
(`{base_url}/NAME/mcp`); `/mcp` exists only with `DEFAULT_UPSTREAM`. The
metadata a client fetches names the URL it connected to as the resource,
and clients compare the two.

**One hostname advertises another in its OAuth metadata** — the proxy is
running with only that other hostname in `MCP_PROXY_BASE_URL`. Adding a host
at the load balancer is not enough; see [Serving several hostnames from one
deployment](#serving-several-hostnames-from-one-deployment).

**Tokens won't refresh** — most IdPs require `offline_access` in the
scope list to issue refresh tokens (`openid profile email
offline_access`). Cognito is the exception — it issues them automatically
once the app client has "Authorization code grant" enabled.

**Web-mode proxy advertises itself as `FastMCPProxy-xxxx`** — set the
`--proxy-name` (and ideally `--proxy-version`, `--proxy-instructions`,
`--proxy-website-url`) flags. See [Identity advertised to downstream
clients](#identity-advertised-to-downstream-clients).

**MCP client doesn't recognise the proxy at all (stdio)** — JSON
syntax errors are by far the most common cause; double-check trailing
commas and quotes. Confirm `uvx` is on PATH and restart the MCP client
completely (not just reload).

**Connection to the upstream fails** — verify the upstream URL is correct
and reachable from the host running the proxy. Browser-test the URL
directly; check for VPN / corporate-proxy interference.

**Debug logging** — `--debug` (CLI) or `MCP_PROXY_DEBUG=1` (env) for
detailed flow tracing. In web mode, FastMCP also logs the routes it
serves at startup — useful for confirming that protected-resource
metadata is being advertised at the expected
`/.well-known/oauth-protected-resource/mcp` path.

**Still stuck?** Check the [examples directory](examples/token_validating_upstream_mcp/)
for a working test setup, and open an issue on GitHub with `--debug`
output (redacted of any secrets).

# Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing,
CI/CD workflows, and the release process.
