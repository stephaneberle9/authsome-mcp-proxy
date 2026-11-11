<!-- omit from toc -->
# Authsome MCP Proxy

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) proxy that
bridges *upstream MCP servers protected by token validation or static
credentials* to MCP clients such as Claude Desktop, Claude Code, Cursor,
Codex, MCP Inspector, and Claude.ai. ("Authsome" as in *awesome*, but with
auth.)

The proxy can run as:

- **Web mode** (`--transport http`, **recommended for end users**) —
  a persistent HTTP server that any MCP client reaches by URL. Downstream
  clients sign in through the standard MCP OAuth flow; the proxy bridges
  it to your IdP and forwards traffic upstream. A single
  instance can serve many users simultaneously and lives behind a normal
  URL (`https://mcp.example.com/mcp`) — no per-user config files,
  subprocess launchers, or local Python toolchains. This is the default
  for non-developer rollouts and the only mode that works with web-only
  clients like Claude.ai.

- **Desktop mode** (`--transport stdio`, the default for backwards
  compatibility, **developer use**) — launched as a subprocess by the MCP
  client (Claude Desktop, Cursor, Codex, Claude Code via `claude mcp
  add --transport stdio`). Each user runs their own instance and the proxy
  performs the OAuth flow against an external OIDC IdP on their behalf.
  Useful when you don't have a server to host the proxy on or when the
  upstream MCP only validates tokens and you want each developer to
  authenticate locally.

- [What Is This For?](#what-is-this-for)
- [Prerequisites](#prerequisites)
- [Web Mode (Recommended)](#web-mode-recommended)
  - [How it works](#how-it-works)
  - [Proxy as authorization server](#proxy-as-authorization-server)
    - [Generic OIDC](#generic-oidc)
    - [AWS Cognito](#aws-cognito)
    - [Google](#google)
    - [Azure (Entra ID)](#azure-entra-id)
    - [ZITADEL](#zitadel)
  - [IdP as authorization server](#idp-as-authorization-server)
    - [Keycloak](#keycloak)
  - [Connecting downstream MCP clients](#connecting-downstream-mcp-clients)
  - [Client ID Metadata Documents (CIMD)](#client-id-metadata-documents-cimd)
  - [Limiting which clients connect](#limiting-which-clients-connect)
  - [Identity advertised to downstream clients](#identity-advertised-to-downstream-clients)
  - [Serving several hostnames from one deployment](#serving-several-hostnames-from-one-deployment)
  - [Surviving restarts](#surviving-restarts)
- [Desktop Mode (Developer Use)](#desktop-mode-developer-use)
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
   Azure, ZITADEL), so downstream MCP clients can identify themselves
   and run the OAuth code flow without modifying the upstream; and

2. **Outbound** — forwarding the user's session token to the upstream
   (the default; works when the upstream and the proxy validate against
   the same IdP), or substituting a configured static header /
   service-account token if the upstream uses a separate credential
   mechanism. See [Advanced: Outbound Credential Substitution](#advanced-outbound-credential-substitution)
   for the latter case.

The proxy presupposes the upstream is itself an *MCP-native* server (one
that exposes the MCP protocol — typically an MCP endpoint backed by a
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

# Web Mode (Recommended)

Run the proxy as a persistent HTTP server. Downstream MCP clients connect
by URL (e.g. `https://mcp.example.com/mcp`). A single instance serves
many users concurrently; each MCP session gets an isolated upstream
connection so users never see each other's traffic.

## How it works

```
Browser           MCP Client (Claude.ai/Code/Inspector)
   │                       │
   │  OAuth login          │  1. register + code + token
   │ ◄────────────────────►│ ◄──────────────────────────────┐
   │                       │                                │
   │                       │  2. tools, prompts, resources  │
   │                       │     (Authorization: Bearer P,  │
   │                       ▼      issued by the proxy)      │
   │            ┌─────────────────────┐                     │
   │            │  authsome-mcp-proxy │  looks up the IdP   │
   │            │  --transport http   │  token U behind P   │
   │            └─────────────────────┘  in its store       │
   │                       │                                │
   │                       │  3. Authorization: Bearer U    │
   │                       ▼   (forwarded)                  │
   │            ┌─────────────────────┐                     │
   │            │   Upstream MCP      │                     │
   │            │   server            │                     │
   │            └─────────────────────┘                     │
   │                                                        │
   └─── Upstream MCP validates U against the same IdP ──────┘
```

The diagram shows the usual case, in which the proxy is itself the OAuth
authorization server its MCP clients talk to. Which of two roles the
proxy takes follows from `--inbound-auth-provider`:

**Proxy as authorization server** (`oidc`, `aws-cognito`, `google`,
`azure`, `zitadel`). MCP clients expect to introduce themselves to the
authorization server at runtime, and these IdPs only know clients that
were registered with them beforehand. The proxy therefore stands between
the two and plays two OAuth 2.0 roles at once: it is a **client** of the
IdP, as one pre-registered application (`OIDC_CLIENT_ID`), and the
**authorization server** for the MCP clients. Clients register and sign
in at the proxy, which sends the user on to the IdP to log in. The MCP
client never sees the IdP's tokens: the proxy keeps them in its store
and issues its own signed tokens that refer to them, swapping one for
the other on every request. The IdP in turn never sees the MCP clients,
only the proxy's one application.

**IdP as authorization server** (`keycloak`). Keycloak lets MCP clients
register with it directly, so the proxy stays out of the sign-in: it
only tells clients that Keycloak is the authorization server and
verifies the tokens Keycloak issues. Clients register and sign in at
Keycloak and hold Keycloak's own tokens. The proxy holds no IdP
credentials and keeps no OAuth state.

Several things further down depend on that role, because they belong to
whoever is the authorization server:

| | Proxy as authorization server | IdP as authorization server |
|---|---|---|
| MCP clients register and sign in at | the proxy | the IdP |
| How a client may identify itself ([CIMD](#client-id-metadata-documents-cimd) or DCR) is up to | the proxy | the IdP |
| The IdP sees | the proxy's one application, whichever client connects | every MCP client as a client of its own |
| [Which clients may connect](#limiting-which-clients-connect) is decided by | the proxy | the IdP |
| The MCP client holds | the proxy's tokens, which refer to the IdP's | the IdP's tokens |
| The proxy keeps | registrations and tokens — see [Surviving restarts](#surviving-restarts) | nothing |

In both roles the token that `--outbound-auth forward` sends to the
upstream MCP server is the IdP's. For the full sequence diagram,
persistence model, and pod-restart implications, see
[docs/oauth-flow.md](docs/oauth-flow.md).

The proxy is IdP-agnostic — pick the inbound provider that matches your
deployment via `--inbound-auth-provider`. The following sections give a
working example for each, grouped by role.

> [!IMPORTANT]
> All examples below assume the upstream MCP server validates tokens
> against the *same* IdP that fronts the proxy (`--outbound-auth forward`,
> the default). If the upstream uses a separate credential mechanism (API
> key, service-account token, etc.), see [Advanced: Outbound Credential Substitution](#advanced-outbound-credential-substitution).

## Proxy as authorization server

With these providers the proxy holds one pre-registered application at
the IdP and is the authorization server for the MCP clients (see
[How it works](#how-it-works)). Register `{proxy-base-url}/auth/callback`
as a redirect URI of that application.

### Generic OIDC

Use this for any OIDC-compliant IdP that MCP clients cannot register
with themselves (older Keycloak, Auth0, Okta, etc.).

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
`{oidc-issuer-url}/.well-known/openid-configuration`.

### AWS Cognito

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

### Google

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

### Azure (Entra ID)

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

### ZITADEL

```bash
uvx authsome-mcp-proxy \
  --transport http \
  --port 8000 \
  --proxy-base-url https://mcp.example.com \
  --inbound-auth-provider zitadel \
  --zitadel-domain my-instance-abc123.zitadel.cloud \
  --oidc-client-id <zitadel-app-client-id> \
  --oidc-client-secret <zitadel-app-client-secret> \
  --oidc-scopes "openid profile email offline_access" \
  https://mcp-upstream.example.com/mcp
```

In the [ZITADEL](https://zitadel.com) Console (ZITADEL Cloud or
self-hosted), add a **Web** application for the proxy with the
authentication method **Code** (the client secret is sent with HTTP
Basic) and `{proxy-base-url}/auth/callback` as redirect URI. ZITADEL
accepts `http://` redirect URIs only with the application's *Development
Mode* switched on. Copy the client secret right away; ZITADEL shows it
only once.

Which project the application goes into matters, because ZITADEL scopes
token audiences to a whole project: a token issued to an application
carries the ID of that application's project in `aud`, without being
asked to.

- With `--outbound-auth forward` (the default), put the proxy's
  application into **the same project as the upstream MCP server's
  application**. The forwarded token then carries the upstream's project
  audience by itself, and `--oidc-scopes` needs no audience scope for
  it. Keep that project dedicated to the MCP server, the proxy's
  application and the upstream's, and do not share it with unrelated
  applications, whose tokens would carry the same audience.
- Only the audiences of *other* projects need requesting: for each
  further ZITADEL project whose APIs the upstream calls with the
  forwarded token, add
  `urn:zitadel:iam:org:project:id:<project-id>:aud` to `--oidc-scopes`.
- With `--outbound-auth static` or `oauth-client-credentials` the token
  never leaves the proxy, so a project of the proxy's own is enough.

The application's **Auth Token Type** (*Token Settings* in the Console)
decides what the upstream receives. The proxy itself works with both
values, **Bearer Token** (the default, which issues opaque access
tokens) and **JWT**, because it validates through introspection. In
forward mode, though, that token goes on to the upstream unchanged, and
an upstream that validates it locally as a JWT (signature against the
JWKS, `iss`, `aud`, `exp`) rejects an opaque token with `401`. So: **an
upstream that validates tokens itself needs Auth Token Type JWT.** An
upstream that introspects tokens works with either.

`--zitadel-domain` takes a bare host, which defaults to HTTPS, or a full
URL such as `http://localhost:8080` for a local instance. The client
secret is required: the proxy validates every ZITADEL access token,
opaque or JWT, through ZITADEL's token introspection endpoint, and
authenticates to it with that secret. Revoked tokens and deactivated
users are therefore rejected on the next request. Tokens issued to
another application of the same project are rejected as well.

For refresh tokens, open the application's *OIDC Settings*, tick the
**Refresh Token** grant type next to *Authorization Code*, and request
`offline_access` as shown above. Without that grant, leave
`offline_access` out of `--oidc-scopes`. With no `--oidc-scopes` at
all, the proxy requests `openid` only.

`--oidc-scopes` are not only requested from ZITADEL: the proxy also
requires each of them on every token, checked against the `scope` field
of the introspection response. ZITADEL returns the requested scopes
there unchanged, the reserved `urn:zitadel:iam:…` ones included, so
audience scopes can be listed like any other.

> [!NOTE]
> No FastMCP release ships a ZITADEL provider yet. The proxy carries a
> copy of the one proposed upstream in
> [PrefectHQ/fastmcp#6392](https://github.com/PrefectHQ/fastmcp/pull/6392)
> until one does, so the setup above is the same as it will be with
> FastMCP's own.

## IdP as authorization server

With this provider the MCP clients register and sign in at the IdP
itself, and the proxy only verifies the resulting tokens (see
[How it works](#how-it-works)).

### Keycloak

For Keycloak ≥ 26.6.0 the proxy uses
[`KeycloakAuthProvider`](https://github.com/PrefectHQ/fastmcp/blob/main/fastmcp_slim/fastmcp/server/auth/providers/keycloak.py),
a `RemoteAuthProvider`. Keycloak supports MCP-compatible Dynamic Client
Registration natively, so the proxy holds **no IdP credentials of its
own** — downstream MCP clients register directly with Keycloak. The
proxy's job reduces to JWT verification + protected-resource metadata
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
natively, so the proxy has to be the authorization server.

## Connecting downstream MCP clients

Clients connect to `{proxy-base-url}/mcp`, `https://mcp.example.com/mcp`
in the examples above:

**Claude.ai:** in *Settings → Connectors → Add custom connector*, paste
the URL. Claude identifies itself to the authorization server and walks
the user through the OAuth flow in the browser.

**Claude Code:**
```bash
claude mcp add --transport http my-server https://mcp.example.com/mcp
```

**MCP Inspector:**
```bash
npx -y @modelcontextprotocol/inspector
```
…then in the UI: set *Transport Type* to **Streamable HTTP**, paste
`https://mcp.example.com/mcp` into *URL*, and — importantly — set
*Connection Type* to **Via Proxy** (the default *Direct* mode bypasses
Inspector's local OAuth helper and breaks the authorization flow against
the proxy). Then click *Connect*.

> [!NOTE]
> On headless hosts (Docker, cloud VM, CI), web mode doesn't
> need a browser on the proxy machine — downstream MCP clients drive the
> OAuth browser flow from wherever the user is sitting. Just expose the
> proxy at a reachable URL and you're done.

## Client ID Metadata Documents (CIMD)

Before an MCP client can send a user to sign in, it has to identify
itself to the authorization server. The MCP specification's way to do
that is the [Client ID Metadata Document][cimd-draft] (CIMD): a client
hosts a small JSON document at an HTTPS URL it controls, and that URL
*is* its `client_id`. The authorization server fetches the document on
first use. Dynamic Client Registration (DCR), where the client registers
at a `/register` endpoint and is handed a random `client_id`, is
[deprecated in the MCP specification][mcp-auth] and kept for
authorization servers and clients that do not support CIMD.

How a client may identify itself is up to the authorization server, so
it depends on the proxy's role (see [How it works](#how-it-works)):

| Role | `--inbound-auth-provider` | CIMD |
|---|---|---|
| Proxy as authorization server | `oidc`, `google`, `azure`, `aws-cognito`, `zitadel` | ✅ the proxy handles CIMD itself, whether or not the IdP knows it |
| IdP as authorization server | `keycloak` | ⚠️ not the proxy's call — clients register directly with Keycloak, so CIMD works only if your Keycloak does. `ENABLE_CIMD` is inert here. |

The rest of this section is about the first role. There the proxy
accepts both: CIMD is **enabled by default**, and DCR stays available
next to it for clients that only support DCR. Turn CIMD off with
`--no-enable-cimd` (or `ENABLE_CIMD=false`). DCR is turned off by a
client allowlist, see
[Limiting which clients connect](#limiting-which-clients-connect).

CIMD has two advantages over DCR. The client keeps one durable identity
across every server it talks to, rather than a different `client_id` per
proxy instance, and that identity names its publisher, which is what
makes an allowlist possible. And because the metadata lives at the
client's own URL, the proxy can re-fetch it after a restart — where a
DCR registration that lived only in the proxy's client store is simply
gone. The client's *session* is not covered by that: its tokens live in
the proxy's store like everyone else's, see
[Surviving restarts](#surviving-restarts).

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
[mcp-auth]: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization

## Limiting which clients connect

Signing in establishes *who* the user is, not *which client software*
they are using. Which MCP clients may connect is a separate decision,
and it matters wherever tool results may only reach vendors you have
vetted, because an MCP client sends the tool results to its LLM. That
decision can only be made by the authorization server, the one party a
client presents its `client_id` to. So where it is made depends on the
proxy's role (see [How it works](#how-it-works)):

- **IdP as authorization server** (`keycloak`): every MCP client
  registers with Keycloak as a client of its own, so Keycloak knows
  which software is connecting. Limit the clients there, with
  Keycloak's
  [client registration policies](https://www.keycloak.org/securing-apps/client-registration#_client_registration_policies):
  its *Trusted Hosts* policy, for one, restricts which hosts may send
  registration requests and which URLs a new client may use. The proxy
  never sees a `client_id`, so its allowlist is not applied; it logs a
  warning at startup if one is set.
- **Proxy as authorization server** (every other provider): neither the
  IdP nor the upstream MCP server can find out which client a user came
  through. Every token the IdP issues names the proxy's own application
  as the authorized party (`azp`, or `client_id`, is `OIDC_CLIENT_ID`),
  whichever MCP client is behind it. Only the proxy can decide, with the
  allowlist the rest of this section describes. By default it accepts
  every client.

`--allowed-client-ids` (or `ALLOWED_CLIENT_IDS`) names the clients that
may connect:

```bash
uvx authsome-mcp-proxy ... --allowed-client-ids "https://claude.ai/"
```

Entries are separated by commas or whitespace. An entry matches a
`client_id` exactly, or, for an `https://` URL ending in `/`, as a
prefix: `https://claude.ai/` admits every client whose
[Client ID Metadata Document](#client-id-metadata-documents-cimd) is
published under that host, which covers Claude
(`https://claude.ai/oauth/mcp-oauth-client-metadata`) and Claude Code
(`https://claude.ai/oauth/claude-code-client-metadata`). The trailing
`/` is what keeps the entry from matching
`https://claude.ai.attacker.example/`, which is why there are no
wildcards. A malformed entry is refused at startup.

With an allowlist set:

- **A client that is not listed is refused** before anything else
  happens: its metadata document is never fetched, it cannot start a
  sign-in, and the token endpoint answers it with `invalid_client`, so
  it cannot refresh tokens it already holds either. Access tokens issued
  earlier stay valid until they expire. Each refusal is logged as a
  warning naming the `client_id`.
- **Dynamic Client Registration is off.** A `client_id` from DCR is
  random and anonymous, so it could never be listed: the `/register`
  endpoint and its entry in the authorization-server metadata disappear,
  and clients registered earlier are refused. Clients that support CIMD
  use that instead, so keep CIMD enabled. If clients that only know DCR
  must keep connecting, leave the allowlist unset; the two cannot be
  combined.
- **A client that sends the proxy's own `OIDC_CLIENT_ID`** instead of
  registering (the "own OAuth client" option of Claude's custom
  connector dialog, Claude Code's `--client-id`) is refused unless that
  ID is listed. Listing it also requires
  `--allowed-upstream-client-redirect-uris` (or
  `ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS`), the redirect URIs such a
  client may use, e.g. `https://claude.ai/api/mcp/auth_callback
  http://localhost:* http://127.0.0.1:*`; the proxy refuses to start
  without it, because that `client_id` alone would let in whoever knows
  it.

The same list applies to every hostname the proxy serves, and the
startup log names the clients accepted, or says that every client is.
A client that redirects to a loopback address, such as Claude Code,
runs on the user's own machine, where any program can present its
`client_id`: the allowlist keeps out other vendors' hosted clients, not
software the user runs locally.

The mechanism comes from
[fastmcp-seaworthy](https://github.com/stephaneberle9/fastmcp-seaworthy#limiting-which-clients-connect),
whose README covers the matching rules in full.

## Identity advertised to downstream clients

In desktop mode the proxy relays the upstream MCP server's identity (name,
version, instructions, website URL, icons) at startup, so the proxy
appears transparent.

In web mode the proxy cannot read the upstream at startup: with
`--outbound-auth forward` the upstream only accepts a user's token, and
no user has connected yet. So the identity is split:

- **Instructions, version, website URL and icons** are relayed from the
  upstream when a client connects. The first handshake fetches them with that
  client's credential; the result is cached for 10 minutes, so a
  redeployed upstream is picked up without restarting the proxy. If the
  fetch fails, the client still connects and sees the proxy's own values.
  If the upstream cannot be reached and you set no version, FastMCP's own
  version is shown.
- **The name** is yours to set. FastMCP also uses the server name
  outside the handshake, where a relayed value would not reach it.
  Unset, it falls back to FastMCP's auto-generated `FastMCPProxy-xxxx`.

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
> backend. That machinery comes from
> [fastmcp-seaworthy](https://github.com/stephaneberle9/fastmcp-seaworthy),
> which other FastMCP servers use the same way.

## Surviving restarts

As the authorization server for its MCP clients (every provider except
`keycloak`, see [How it works](#how-it-works)), the proxy keeps state:
the clients registered through DCR,
the upstream IdP's access and refresh tokens, and the mapping from the
tokens it issued to them. It signs those tokens with a signing key. Both
decide what a restart costs:

- **Store.** By default the state lives in an encrypted file store under
  `${FASTMCP_HOME}/oauth-proxy/` (`/app/.local/share/fastmcp/oauth-proxy/`
  in the published image). On a VM with a normal disk that is durable. In
  a container whose filesystem does not survive a restart, such as a
  Kubernetes `Deployment`, every restart loses all registrations and signs
  every user out — CIMD clients included, which keep only their
  registration. A volume at that path helps, but turns the proxy into a
  single-replica `StatefulSet`.
- **Signing key.** Unset, the proxy derives the signing key — and from it
  the store's encryption key and directory — from the upstream client
  secret (`OIDC_CLIENT_SECRET`). Rotating that secret then invalidates every
  issued token and strands everything stored, volume or not.

A restart-safe deployment therefore sets both a signing key and an
external store backend, shared by every replica: a DynamoDB table or a
table in a PostgreSQL database. With DynamoDB:

```bash
uvx 'authsome-mcp-proxy[dynamodb]' ... \
  --jwt-signing-key "$(openssl rand -base64 32)" \
  --store-backend dynamodb \
  --store-dynamodb-table authsome-mcp-proxy-oauth-state \
  --store-dynamodb-region eu-central-1
```

Keep the signing key in a secret store and stable across deployments —
generating it at startup, as in this one-liner, would defeat the purpose.
With an external backend the proxy refuses to start without one. The
values written to an external store are Fernet-encrypted with a key
derived from it, the same way FastMCP encrypts its own file store, so the
table never holds an upstream token in plaintext. A `JWT_SIGNING_KEY` is
worth setting with the default file store too: it decouples the stored
state from the upstream client secret. It must be at least 32 characters;
a shorter one is refused at startup. The startup log names the store and
signing key in use. Only the stored values are encrypted: each entry's
collection, key and expiry, among them client IDs and, while they are
valid, authorization codes, are readable to whoever can read the table, so
keep write access to it with the proxy alone. An entry that is not
encrypted is ignored rather than trusted. The settings and the store come
from [fastmcp-seaworthy](https://github.com/stephaneberle9/fastmcp-seaworthy),
so other FastMCP servers built on it read the same variables.

**DynamoDB.** The backend needs the `dynamodb` extra, which the published
container image already includes. Credentials and region come from the
AWS SDK's usual chain (IRSA or EKS Pod Identity, instance profile,
`AWS_*` environment variables); `AWS_ENDPOINT_URL_DYNAMODB` points it at
DynamoDB Local for testing. Create the table with your infrastructure
code:

| Property | Value |
|---|---|
| Partition key | `collection` (String) |
| Sort key | `key` (String) |
| Time to live | enabled on the attribute `ttl` |
| Billing mode | any; on-demand fits the access pattern |

The proxy needs `dynamodb:DescribeTable`, `dynamodb:DescribeTimeToLive`,
`dynamodb:GetItem`, `dynamodb:PutItem` and `dynamodb:DeleteItem` on the
table. It checks the table at startup and refuses to start, naming the
table, if it is missing. `--store-dynamodb-auto-create` makes it create a
missing table instead (on-demand, TTL enabled); that additionally needs
`dynamodb:CreateTable` and `dynamodb:UpdateTimeToLive`, and is off by
default so the proxy can run with the narrower permissions. Without TTL
enabled on the table, the proxy also needs `dynamodb:UpdateTimeToLive` to
enable it at startup.

**PostgreSQL.** The backend needs the `postgres` extra
(`uvx 'authsome-mcp-proxy[postgres]'`), which the published container
image already includes. It is the external store for deployments
outside AWS: a docker-compose stack, a PaaS with a managed PostgreSQL
service, or any setup that already runs a database.

```bash
export JWT_SIGNING_KEY=...   # from your secret store
export STORE_POSTGRES_URL='postgresql://proxy:<password>@db.example.com:5432/appdb?sslmode=require'
uvx 'authsome-mcp-proxy[postgres]' ... --store-backend postgres
```

Set the connection URL through the `STORE_POSTGRES_URL` environment
variable rather than `--store-postgres-url`: it usually carries the
database password, and command-line arguments show up in process
listings. The proxy never logs or echoes the URL. The startup line and
startup errors name the table, the database, and the host and port
only, and a database driver error that would quote the URL or the
password has both replaced by `***`. `postgres://` works as a scheme
too, and libpq query parameters such as `sslmode` are passed on.
Percent-encode `@`, `/`, `?` and `#` in the user name and password
(`%40`, `%2F`, `%3F`, `%23`); an unencoded one is refused at startup.

Create the table with your migrations, or let
`--store-postgres-auto-create` create it:

```sql
CREATE TABLE fastmcp_oauth_state (
    collection TEXT NOT NULL,
    key TEXT NOT NULL,
    value JSONB NOT NULL,
    ttl DOUBLE PRECISION,
    created_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (collection, key)
);
CREATE INDEX idx_fastmcp_oauth_state_expires_at
    ON fastmcp_oauth_state (expires_at) WHERE expires_at IS NOT NULL;
```

The proxy's database role needs `SELECT`, `INSERT`, `UPDATE` and
`DELETE` on the table; auto-create additionally needs `CREATE` on the
schema, and is off by default so the proxy can run with the narrower
role. `STORE_POSTGRES_TABLE` renames the table and optionally pins it to
a schema, as in `oauth.fastmcp_oauth_state`; the schema must exist.
Names are lowercase letters, digits and underscores. At startup the
proxy checks that the table resolves where its queries will look for it
and refuses to start, naming the table, if it does not.

In a docker-compose stack, have the proxy wait for the database, since
it connects at startup and exits if it cannot:

```yaml
services:
  mcp-proxy:
    image: ghcr.io/stephaneberle9/authsome-mcp-proxy:latest
    environment:
      # ... upstream URL, base URL and inbound provider settings ...
      JWT_SIGNING_KEY: ${JWT_SIGNING_KEY}
      STORE_BACKEND: postgres
      STORE_POSTGRES_URL: postgresql://proxy:${POSTGRES_PASSWORD}@db:5432/proxy
      STORE_POSTGRES_AUTO_CREATE: "true"
    depends_on:
      db:
        condition: service_healthy
  db:
    image: postgres:17
    environment:
      POSTGRES_USER: proxy
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: proxy
    volumes:
      - db-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U proxy -d proxy"]
      interval: 5s
      retries: 10
volumes:
  db-data:
```

On a PaaS, bind or attach the platform's managed PostgreSQL service and
set `STORE_POSTGRES_URL` from the connection URL the platform hands out,
through its secret or environment mechanism rather than the start
command. Platform-generated passwords often contain `@` or `/`, which
must be percent-encoded as described above. Where the database is
shared with an application, a schema-qualified `STORE_POSTGRES_TABLE`
keeps the proxy's table out of the application's schema.

**Expired rows are not deleted.** The store records each entry's expiry
and ignores expired entries on read, but nothing removes them, so the
table keeps every expired authorization code and token record. Unlike
DynamoDB, PostgreSQL has no time to live of its own. Prune the table
periodically, e.g. from a cron job or `pg_cron`; the partial index on
`expires_at` keeps the statement cheap:

```sql
DELETE FROM fastmcp_oauth_state WHERE expires_at < now();
-- or, with a qualified STORE_POSTGRES_TABLE:
DELETE FROM oauth.fastmcp_oauth_state WHERE expires_at < now();
```

All of these settings are inert for `--inbound-auth-provider keycloak`,
where Keycloak is the authorization server and the proxy keeps no OAuth
state.

# Desktop Mode (Developer Use)

The proxy is launched as a subprocess by the MCP client, performs the
OAuth flow against an external OIDC IdP on the developer's behalf,
caches tokens locally, and forwards them upstream.

Use desktop mode when:

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

**Upstream coordinates** — required:

| Env var | CLI flag | Description |
|---|---|---|
| `UPSTREAM_MCP_URL` | (positional) | URL of the upstream MCP server. |

**Proxy runtime** — all optional:

| Env var | CLI flag | Default | Description |
|---|---|---|---|
| `MCP_PROXY_TRANSPORT` | `--transport {stdio,http}` | `stdio` | Which transport to serve on: `stdio` is desktop mode, `http` is web mode. |
| `MCP_PROXY_HOST` | `--host` | `0.0.0.0` | Web-mode bind address. |
| `MCP_PROXY_PORT` | `--port` | `8000` | Web-mode listen port. |
| `MCP_PROXY_BASE_URL` | `--proxy-base-url` | _required for http_ | Publicly reachable URL of the proxy. Used to advertise auth metadata to downstream clients. Accepts a comma-separated list to serve several hostnames, each as its own OAuth identity — see [Serving several hostnames from one deployment](#serving-several-hostnames-from-one-deployment). |
| `MCP_PROXY_DEBUG` | `--debug` | _off_ | Enable debug logging. |

**Server identity advertised to downstream clients** (web mode):

| Env var | CLI flag | Description |
|---|---|---|
| `MCP_PROXY_NAME` | `--proxy-name` | Display name (e.g. `"Acme Analytics"`). |
| `MCP_PROXY_VERSION` | `--proxy-version` | Display version. Optional override: unset, the upstream's version is relayed. |
| `MCP_PROXY_INSTRUCTIONS` | `--proxy-instructions` | Tool-selection hints for the LLM. Optional override: unset, the upstream's instructions are relayed. |
| `MCP_PROXY_WEBSITE_URL` | `--proxy-website-url` | Project URL shown in client UIs. Optional override: unset, the upstream's website URL is relayed. |

**Inbound auth** (web mode — pick a provider, then supply the fields it
needs):

| Env var | CLI flag | Description |
|---|---|---|
| `INBOUND_AUTH_PROVIDER` | `--inbound-auth-provider {oidc,keycloak,aws-cognito,google,azure,zitadel}` | Which provider class to use. |
| `OIDC_ISSUER_URL` | `--oidc-issuer-url` | OIDC issuer / Keycloak realm URL. |
| `OIDC_CLIENT_ID` | `--oidc-client-id` | OAuth client ID at the IdP. |
| `OIDC_CLIENT_SECRET` | `--oidc-client-secret` | OAuth client secret (required for `aws-cognito` and `zitadel`; optional for `oidc`/`google`/`azure`; unused for `keycloak`). |
| `OIDC_SCOPES` | `--oidc-scopes` | Space-separated scopes. |
| `AUDIENCE` | `--audience` | JWT `aud` claim to require (oidc/keycloak; recommended for production). |
| `COGNITO_USER_POOL_ID` | `--cognito-user-pool-id` | AWS Cognito user pool ID. |
| `COGNITO_AWS_REGION` | `--cognito-aws-region` | AWS region for the Cognito user pool. |
| `AZURE_TENANT_ID` | `--azure-tenant-id` | Azure AD tenant ID. |
| `AZURE_IDENTIFIER_URI` | `--azure-identifier-uri` | Azure Application ID URI used for scope prefixing. |
| `ZITADEL_DOMAIN` | `--zitadel-domain` | ZITADEL instance domain (bare host, defaults to HTTPS) or full URL. |
| `ENABLE_CIMD` | `--enable-cimd` / `--no-enable-cimd` | Accept Client ID Metadata Documents from downstream clients. On by default — see [Client ID Metadata Documents (CIMD)](#client-id-metadata-documents-cimd). |

**OAuth proxy state** (web mode, inert for `keycloak` — see
[Surviving restarts](#surviving-restarts)):

| Env var | CLI flag | Default | Description |
|---|---|---|---|
| `JWT_SIGNING_KEY` | `--jwt-signing-key` | _derived from `OIDC_CLIENT_SECRET`_ | Signs the tokens the proxy issues and keys its store's encryption. At least 32 characters. Required with a `STORE_BACKEND` other than `file`. |
| `STORE_BACKEND` | `--store-backend {file,dynamodb,postgres}` | `file` | Where client registrations and sessions are kept. `dynamodb` needs the `dynamodb` extra, `postgres` the `postgres` extra. |
| `STORE_DYNAMODB_TABLE` | `--store-dynamodb-table` | _required for `dynamodb`_ | DynamoDB table name. |
| `STORE_DYNAMODB_REGION` | `--store-dynamodb-region` | _AWS SDK default_ | AWS region of the table. |
| `STORE_DYNAMODB_AUTO_CREATE` | `--store-dynamodb-auto-create` / `--no-store-dynamodb-auto-create` | _off_ | Create the table at startup when it is missing, instead of refusing to start. |
| `STORE_POSTGRES_URL` | `--store-postgres-url` | _required for `postgres`_ | PostgreSQL connection URL, `postgresql://user:password@host:5432/database`. Usually carries the database password: set it through the environment, not the flag, since command-line arguments show up in process listings. Never logged. |
| `STORE_POSTGRES_TABLE` | `--store-postgres-table` | `fastmcp_oauth_state` | Table name, optionally schema-qualified as `schema.table`. |
| `STORE_POSTGRES_AUTO_CREATE` | `--store-postgres-auto-create` / `--no-store-postgres-auto-create` | _off_ | Create the table at startup when it is missing, instead of refusing to start. |

**Client allowlist** (web mode, not applied for `keycloak` — see
[Limiting which clients connect](#limiting-which-clients-connect)):

| Env var | CLI flag | Default | Description |
|---|---|---|---|
| `ALLOWED_CLIENT_IDS` | `--allowed-client-ids` | _every client_ | The OAuth clients that may connect, separated by commas or whitespace: exact `client_id`s, or `https://` URLs ending in `/` that allow every `client_id` under them, e.g. `https://claude.ai/`. Set, Dynamic Client Registration is off. |
| `ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS` | `--allowed-upstream-client-redirect-uris` | _none_ | The redirect URIs a client sending `OIDC_CLIENT_ID` itself may use, e.g. `http://localhost:*`. Required when `ALLOWED_CLIENT_IDS` lists `OIDC_CLIENT_ID`, and applied to that client only. |

**Outbound auth** (web mode — `forward` is the default and needs no
extra fields):

| Env var | CLI flag | Description |
|---|---|---|
| `OUTBOUND_AUTH` | `--outbound-auth {forward,oauth-client-credentials,static}` | Outbound mechanism. |
| `OUTBOUND_TOKEN_URL` | `--outbound-token-url` | Token endpoint for `oauth-client-credentials`. |
| `OUTBOUND_CLIENT_ID` | `--outbound-client-id` | Client ID for `oauth-client-credentials`. |
| `OUTBOUND_CLIENT_SECRET` | `--outbound-client-secret` | Client secret for `oauth-client-credentials`. |
| `OUTBOUND_HEADER_NAME` | `--outbound-header-name` | Header name for `static` (default `Authorization`). |
| `OUTBOUND_HEADER_VALUE` | `--outbound-header-value` | Literal header value for `static`. |

**Inbound (desktop mode)** — only `OIDC_*` apply; transport and inbound
auth are not exposed downstream since the MCP client launches the proxy
as a trusted subprocess:

| Env var | CLI flag | Default | Description |
|---|---|---|---|
| `OIDC_REDIRECT_URL` | `--oidc-redirect-url` | `http://localhost:8080/auth/callback` | Local OAuth callback URL. |

Run `uvx authsome-mcp-proxy --help` for the always-current list.

# Credential Management

Tokens obtained in **desktop mode** (the proxy's OAuth code flow) are
cached in `~/.cache/authsome-mcp-proxy-<version>/` (where `<version>`
is the installed package version) as a SQLite database:

```
~/.cache/authsome-mcp-proxy-<version>/
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

In **web mode** the proxy has no such cache. Each downstream MCP client
holds the tokens it obtained from the authorization server and manages
its own cache; what the proxy itself stores is described in
[Surviving restarts](#surviving-restarts).

**Headless desktop-mode first run**: if your desktop-mode deployment
target has no
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

**Browser doesn't open (desktop mode)** — check that port 8080 (or your
custom redirect port) isn't blocked, manually open the URL shown in the
proxy logs, and verify your firewall isn't blocking localhost
connections.

**`401 Unauthorized` from the upstream** — verify `OIDC_ISSUER_URL`
matches the IdP your upstream validates against and check requested
scopes; in desktop mode, clear the cache
(`rm -rf ~/.cache/authsome-mcp-proxy*`) before retrying. Run with
`--debug` for token-level diagnostics. With ZITADEL,
an upstream that validates tokens itself needs the application's Auth
Token Type set to JWT and its own project in the token's audience — see
[ZITADEL](#zitadel).

**A client that used to connect is refused, or `/register` returns
`404`** — a client allowlist is set (`ALLOWED_CLIENT_IDS`); the startup
log names the clients it accepts. See
[Limiting which clients connect](#limiting-which-clients-connect).

**`redirect_uri mismatch` from the IdP** — add the proxy's callback URL
to the OAuth client's allowed redirect URIs at the IdP. For desktop mode
that's `http://localhost:8080/auth/callback` (or whatever
`OIDC_REDIRECT_URL` is set to); for web mode it's
`{MCP_PROXY_BASE_URL}/auth/callback`. The match has to be exact, including
trailing slashes. When `MCP_PROXY_BASE_URL` lists several hostnames, *each*
one needs its own callback registered — a hostname whose callback is missing
fails only at the end of the flow, after the user has already logged in.

**One hostname advertises another in its OAuth metadata** — the proxy is
running with only that other hostname in `MCP_PROXY_BASE_URL`. Adding a host
at the load balancer is not enough; see [Serving several hostnames from one
deployment](#serving-several-hostnames-from-one-deployment).

**Tokens won't refresh** — most IdPs require `offline_access` in the
scope list to issue refresh tokens (`openid profile email
offline_access`). Cognito is the exception — it issues them automatically
once the app client has "Authorization code grant" enabled.

**Web-mode proxy advertises itself as `FastMCPProxy-xxxx`** — set the
`--proxy-name` flag; the version, instructions and website URL are
relayed from the upstream. See [Identity advertised to downstream
clients](#identity-advertised-to-downstream-clients).

**MCP client doesn't recognise the proxy at all (desktop mode)** — JSON
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
