<!-- omit from toc -->
# OAuth flow: MCP client ↔ Authsome MCP Proxy ↔ upstream IdP

In-depth walkthrough of the OAuth dance behind `authsome-mcp-proxy`.
The proxy supports two deployment modes with very different OAuth
choreographies; this document covers both, plus what each party stores
and where.

- [Deployment modes at a glance](#deployment-modes-at-a-glance)
- [MCP client compatibility matrix](#mcp-client-compatibility-matrix)
- [Web-connector (HTTP) mode](#web-connector-http-mode)
  - [The proxy's two hats](#the-proxys-two-hats)
  - [The two flows stitched together](#the-two-flows-stitched-together)
  - [Detailed step-by-step](#detailed-step-by-step)
  - [Where the client-side record lives (per client)](#where-the-client-side-record-lives-per-client)
  - [Reconciling with classical (non-proxied) OAuth intuitions](#reconciling-with-classical-non-proxied-oauth-intuitions)
  - [What persists, what doesn't](#what-persists-what-doesnt)
  - [Implications for pod-restart resilience](#implications-for-pod-restart-resilience)
- [Desktop (stdio) mode](#desktop-stdio-mode)
  - [The proxy's single hat](#the-proxys-single-hat)
  - [The single flow](#the-single-flow)
  - [Detailed step-by-step](#detailed-step-by-step-1)
  - [Where the cache lives](#where-the-cache-lives)
  - [Reconciling with classical (non-proxied) OAuth intuitions](#reconciling-with-classical-non-proxied-oauth-intuitions-1)
  - [Persistence and failure modes](#persistence-and-failure-modes)

## Deployment modes at a glance

| Aspect | Web-connector (`--transport http`) | Desktop (`--transport stdio`) |
|---|---|---|
| Where the proxy runs | Persistent HTTP server, typically in Kubernetes or another long-running deployment | Local subprocess on the user's machine, launched by the MCP client |
| Transport to the MCP client | HTTP / streamable JSON-RPC | stdio JSON-RPC |
| Auth between MCP client and proxy | Full OAuth 2.0 + DCR + PKCE | None — local trust (the MCP client launches the proxy as its child) |
| Who registers with the upstream IdP | The proxy, once, statically | The proxy, once, statically (per user) |
| Who does the OAuth flow against the upstream IdP | The proxy, on behalf of every MCP client that connects | The proxy, on behalf of the single local user |
| Where tokens are cached | The upstream IdP's tokens **in the proxy's store** (an encrypted file store by default, or an external backend); the proxy's own tokens, which refer to them, **on the MCP client** | On the proxy's filesystem (local user's home directory) |
| Browser pops up on which machine | The MCP client's user's machine (could be remote — e.g. Cowork in a browser) | The local user's machine |
| Concurrency | Many users share one proxy instance, each with isolated upstream sessions | Single user per proxy process |

## MCP client compatibility matrix

| MCP client | Web-connector mode | Desktop mode (proxy as stdio subprocess) |
|---|---|---|
| Claude Desktop | Indirectly via `mcp-remote` as bridge | ✅ native (configure in `claude_desktop_config.json` with `command`/`args`) |
| Claude Code | ✅ native (`claude mcp add --transport http`) | ✅ native (`claude mcp add --transport stdio`) |
| Cursor | Indirectly via `mcp-remote` | ✅ native |
| Codex | Indirectly via `mcp-remote` | ✅ native |
| MCP Inspector | ✅ native (HTTP transport) | ✅ native (stdio transport) |
| Claude.ai / Cowork | ✅ native (custom connector URL) | ❌ cannot launch local subprocesses; web-connector mode only |

> `mcp-remote` (npm) is an HTTP↔stdio bridge for clients that don't speak
> HTTP MCP natively. In web-connector mode it lets Claude Desktop / Cursor
> / Codex reach a remote proxy. In desktop mode it isn't involved at all
> — this proxy is itself the stdio server.

## Web-connector (HTTP) mode

### The proxy's two hats

In web-connector mode the proxy wears two OAuth 2.0 hats simultaneously,
and the architecture only makes sense once you separate them:

| Hat | Counterparty | Role | Credentials it holds |
|---|---|---|---|
| **OAuth 2.0 _client_** | Upstream IdP / Authorization Server (Cognito, Keycloak, Google, Azure, generic OIDC) | The proxy is a single, pre-registered confidential client of the upstream IdP. | Static `client_id` + `client_secret` for the upstream IdP, loaded from the proxy's env (`OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET`). |
| **OAuth 2.0 _Authorization Server_** | The MCP client (Claude.ai/Cowork, Inspector, `mcp-remote`, …) | The proxy exposes a full OAuth AS surface (`/register`, `/authorize`, `/token`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/...`) with **Dynamic Client Registration** (RFC 7591) and **Client ID Metadata Documents** (CIMD, SEP-991). MCP clients either self-register at runtime or present an HTTPS URL as their `client_id`. | None per-MCP-client at registration time — a DCR client gets its own proxy-issued `client_id` (and `client_secret` if confidential); a CIMD client brings its own, and the proxy fetches its metadata from that URL. |

**The tokens the proxy hands to MCP clients are its own.** It keeps the
upstream IdP's access and refresh tokens in its store and issues the MCP
client a short JWT, signed with its signing key, that refers to them by
an ID. On every request it verifies that JWT, looks up the upstream
token behind it, and validates the upstream token against the IdP. This
is what `OUTBOUND_AUTH=forward` relies on: the bearer it sends to the
upstream MCP server is the upstream IdP's token found in the store, not
the one the MCP client presented (the upstream MCP server validates it
against the same IdP, which is the standard deployment). The MCP client
never sees an upstream token.

Why bridge DCR onto a static-client IdP at all? MCP clients
(Claude.ai/Cowork, Inspector, `mcp-remote`, …) expect to self-register
via DCR. Most enterprise IdPs (Cognito, Google) only support static
client registration. The proxy stands between the two and translates:
each DCR'd MCP client gets its own identity at the proxy, while all
DCR'd clients share the proxy's single pre-registered identity at the
upstream IdP.

CIMD changes only the left-hand side of that translation. A CIMD client
skips `/register` entirely: it sends its metadata-document URL as
`client_id`, the proxy fetches and caches that document (HTTPS only,
public addresses only, no redirects, 5 KB cap — FastMCP's SSRF-hardened
fetcher), and from there the flow is identical. The upstream side is
untouched: CIMD clients share the same single pre-registered identity at
the IdP that DCR clients do. It is on by default and switchable with
`ENABLE_CIMD` / `--no-enable-cimd`; for `INBOUND_AUTH_PROVIDER=keycloak`
it is inert, because there Keycloak — not the proxy — is the AS.

### The two flows stitched together

```
MCP client                    proxy                       Upstream IdP / AS
──────────                    ─────                       ─────────────────
 (1) opens browser ──── /authorize ────────────────────────────►
                            │
                            └─── redirects browser ──── /authorize ──►
                                                                      │
                                                      user logs in    │
                                                                      │
                                  ◄── redirects browser
                                  /callback?code=UPSTREAM_CODE   (a)
                                  │
                          ┌───────┘
                          │
                          │ PROXY  /token (server-to-server)
                          │ ───────────────────────── ──────────────►
                          │   grant_type=authorization_code
                          │   code=UPSTREAM_CODE
                          │   client_id=PROXY_STATIC_UPSTREAM_ID
                          │   client_secret=PROXY_STATIC_UPSTREAM_SECRET  ← THE SECRET
                          │ ◄────────── access_token+refresh_token
                          │
                          │ stores upstream tokens, indexed by a NEW
                          │ proxy-issued auth code = PROXY_CODE
                          │
                          │ redirects browser ──┐
                          │                     ▼
   ◄── <mcp-client-redirect>?code=PROXY_CODE  (b)
   │
   │ MCP CLIENT  /token ─────────────────────►
   │   grant_type=authorization_code
   │   code=PROXY_CODE
   │   code_verifier=<PKCE>             ← no secret; PKCE proves the MCP
   │                                       client is the same DCR registration
   │                                       that initiated the flow
   │ ◄───── proxy moves the upstream tokens it stored against
   │        PROXY_CODE into its token store, and returns its OWN
   │        access + refresh token that refer to them
   │
   ▼
 has proxy-issued access_token + refresh_token (location depends on client)
```

The proxy is the **client** in the upper half (its OAuth-2.0-client hat)
and the **Authorization Server** in the lower half (its DCR-enabled-AS
hat). The two halves are independent OAuth flows that the proxy
stitches together through the temporary `PROXY_CODE`.

### Detailed step-by-step

| # | Wire event | Server-side record (proxy's store, Fernet-encrypted — see [What persists](#what-persists-what-doesnt)) | Client-side record (location depends on the MCP client — see below) |
|---|---|---|---|
| 1 | MCP client → proxy: `POST /register` (DCR, RFC 7591) — **skipped by CIMD clients**, which send their document URL as `client_id` and let the proxy fetch it in step 2a | **DCR client record** — `{dcr_client_id, redirect_uris, scopes, …}`, registered as a public client (no secret). What the proxy looks up later to recognise this particular MCP client. Bridges DCR onto the proxy's single pre-registered upstream client. | **Client credentials** — the `dcr_client_id` the proxy just issued back. Reused on every future flow against this server. |
| 2a | MCP client → proxy: `GET /authorize` | **Transaction state** — `{txn_id, state, code_challenge, redirect_uri, requested_scopes, dcr_client_id, …}`. Short-lived; consumed in step 3. | *(in-memory PKCE verifier only — not on disk)* |
| 2b | proxy → upstream IdP: `GET /authorize` (via browser redirect) | *(no new persistent record — the transaction state from 2a is updated with the upstream-side `state` value)* | *(nothing — browser only)* |
| 3a | upstream IdP → proxy: `GET /callback?code=UPSTREAM_CODE` (via browser redirect) | **Transient** — upstream auth code held in memory until 3b completes. | *(nothing — the browser is currently on the proxy's domain)* |
| 3b | proxy → upstream IdP: `POST /token` (server-to-server) | **Upstream tokens received** — the proxy authenticates with its own upstream `client_secret` (loaded from env). Receives the real upstream `access_token` + `refresh_token`. Stores them, short-lived, indexed by a freshly-generated `PROXY_CODE`. | *(nothing — server-to-server call)* |
| 3c | proxy → MCP client: redirect browser to `<mcp-client-redirect>?code=PROXY_CODE` | *(no new record — `PROXY_CODE` was created in 3b)* | *(nothing yet — the local callback handler is about to fire)* |
| 3d | MCP client → proxy: `POST /token` (PKCE, no secret) | Proxy verifies `code_verifier` against the `code_challenge` from step 2a and deletes `PROXY_CODE`. It moves the upstream tokens into the **upstream token store** (kept until the longest-lived token expires), issues its own access and refresh token — JWTs signed with the proxy's signing key, each carrying a random `jti` — and stores a **`jti` → upstream token mapping** for each, plus **refresh-token metadata** keyed by a hash of the refresh token. | **Proxy-issued access token + refresh token** — not the upstream IdP's. The MCP client puts the access token in `Authorization: Bearer …` on every subsequent JSON-RPC frame; when it expires, it calls `/token` again with `grant_type=refresh_token`. |
| 4 | MCP client → proxy: `POST /mcp` (every JSON-RPC frame) | Proxy verifies the bearer's signature with its signing key, **looks up the upstream token** through the `jti` mapping, and validates that upstream token against the IdP (JWKS, cached in memory), refreshing it upstream first if it is about to expire. A bearer whose mapping is gone is rejected as invalid. In `OUTBOUND_AUTH=forward` the **upstream** token is what goes to the upstream MCP server. | *(no change — reuses the cached access token; silently runs the `/token` refresh dance when expired)* |

### Where the client-side record lives (per client)

| MCP client | Persistence layer |
|---|---|
| `mcp-remote` (npm) | `~/.mcp-auth/<server-hash>/` on local disk |
| MCP Inspector | In-memory only — re-auths on every session |
| Claude.ai / Cowork | Anthropic-managed server-side state — persists across browser sessions and devices |
| Claude Desktop / Cursor / Codex | Via `mcp-remote` (when used as a stdio bridge): `~/.mcp-auth/<server-hash>/` |

Server-side state on the proxy is uniform regardless of which MCP client
is talking to it.

### Reconciling with classical (non-proxied) OAuth intuitions

| Classical OAuth concept | Where it lives here |
|---|---|
| Confidential client with `client_secret` — calls `/token` from its callback handler | **The proxy.** The proxy is the upstream IdP's registered confidential client. The upstream `client_secret` lives in the proxy's env vars only. Used in step **3b**. |
| Public client with PKCE — calls `/token` from its local callback | **The MCP client.** It's a DCR'd public client of the proxy. No secret; PKCE binds the `/token` call to the `/authorize` call. Used in step **3d**. |
| `/callback` endpoint | Two different ones: **the proxy's `/callback`** (where the upstream IdP redirects, step 3a) and **the MCP client's redirect URI** (where the proxy redirects, step 3c — e.g. `http://localhost:XXXX/oauth/callback` for `mcp-remote`, Anthropic-hosted for Claude.ai/Cowork). |
| Authorization code | Two different ones: **`UPSTREAM_CODE`** (upstream-IdP-issued, consumed by the proxy in 3b) and **`PROXY_CODE`** (proxy-issued, consumed by the MCP client in 3d). |

### What persists, what doesn't

After step 3d completes:

- **Server side (proxy):** the proxy's store holds, per collection:
  - `mcp-oauth-proxy-clients` — the **DCR client records** from step 1
    (CIMD clients are not stored; the proxy caches their documents in
    memory and re-fetches them);
  - `mcp-upstream-tokens` — the **upstream IdP's access and refresh
    tokens**;
  - `mcp-jti-mappings` — the mapping from each proxy-issued token's
    `jti` to the upstream tokens;
  - `mcp-refresh-tokens` — metadata of the proxy-issued refresh tokens.

  Transaction state and `PROXY_CODE` are short-lived and gone. Every
  entry is Fernet-encrypted with a key derived from the proxy's signing
  key.
- **Client side (MCP client):** the **DCR `client_id`** from step 1,
  plus the **proxy-issued access + refresh tokens** received in step 3d.
  Where these live depends on the MCP client (see table above).

The **signing key** both signs the proxy's tokens and, through a key
derivation, encrypts the store. Unless `JWT_SIGNING_KEY` sets it, FastMCP
derives it from the upstream `client_secret`.

The **store** is FastMCP's encrypted file store under
`${FASTMCP_HOME}/oauth-proxy/<key>/` by default, where `<key>` is a
fingerprint of the encryption key. `${FASTMCP_HOME}` defaults to
`${HOME}/.local/share/fastmcp/` and resolves to
`/app/.local/share/fastmcp/` inside the container with the project's
default `HOME=/app`. `STORE_BACKEND` replaces it with an external
backend (currently DynamoDB), which the proxy wraps in the same Fernet
encryption; an external backend requires `JWT_SIGNING_KEY`. When several
hostnames are served, all of their providers share the one store.

### Implications for pod-restart resilience

If the proxy pod restarts with the default file store and no persistent
volume backing its directory, the whole store is lost:

- The **DCR registry dies** → every MCP client that was registered now
  holds a `dcr_client_id` the proxy doesn't recognise. On the next
  `/authorize` or `/token` call the proxy returns `invalid_client`
  (RFC 6749 §5.2). Well-behaved MCP clients drop their local cache for
  the server and re-run the full flow (browser popup, user login, fresh
  DCR registration); clients that register once and cache the result
  need manual re-registration.
- **Every session dies** → the tokens MCP clients hold are the proxy's
  own, and the `jti` mappings to the upstream tokens behind them are gone.
  The signature still verifies — the signing key is derived the same way
  after the restart — but the lookup fails, so every request is rejected
  as unauthorized and every user has to sign in again.

**CIMD clients keep their registration, not their session.** Their
`client_id` is a URL the client hosts, not a record the proxy issued, so
a restarted proxy simply re-fetches the document and recognises them
again — no re-registration. Their tokens, however, refer into the store
like everyone else's, so the user still has to sign in again.

A **rotation of the upstream client secret** has the same effect even on
a persistent volume when `JWT_SIGNING_KEY` is unset: the signing key
changes with the secret, so every issued token fails signature
validation, and the encryption key and store directory change with it,
leaving the old records unreachable.

A persistent volume at `${FASTMCP_HOME}/oauth-proxy/` therefore keeps
registrations and sessions only until the next secret rotation, and makes
the proxy a single-replica `StatefulSet` pinned to the volume's
availability zone. The alternative that keeps both, survives rotations
and allows several replicas is a stable `JWT_SIGNING_KEY` plus an
external store backend (`STORE_BACKEND=dynamodb`) that every replica
shares; the README section
[Surviving restarts](../README.md#surviving-restarts) describes the setup.

## Desktop (stdio) mode

### The proxy's single hat

In desktop mode the proxy is launched as a stdio subprocess of a single
MCP client running on the same machine — Claude Desktop, Claude Code,
Cursor, Codex, or MCP Inspector. The MCP client speaks JSON-RPC to the
proxy over stdin/stdout. There is **no auth between the MCP client and
the proxy** — they share a process tree and trust each other locally.

The proxy wears only **one OAuth 2.0 hat** here: it is an **OAuth 2.0
client** of the upstream IdP, doing the classical Authorization Code +
PKCE flow on behalf of the single local user. No DCR, no AS surface, no
two-flow stitching. Just one client, one flow, one user.

This requires the user to have pre-registered an OAuth client with the
upstream IdP themselves (the proxy is *that* client) and to supply the
credentials via env vars: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET` (optional for public clients), `OIDC_SCOPES`,
`OIDC_REDIRECT_URL`.

### The single flow

```
Browser                  MCP client                   proxy                Upstream IdP / AS    Upstream MCP
                         (Claude Desktop /            (local stdio
                          Code / Inspector / …)        subprocess)
                                │
                                │ launches as subprocess
                                │ ───────────────────►│
                                │                     │
                                │ JSON-RPC over stdio │
                                │ ◄──────────────────►│
                                │                     │
                                │                     │ first upstream call needs auth
                                │                     │
                                │                     │ start tiny HTTP listener on
                                │                     │ OIDC_REDIRECT_URL (e.g.
                                │                     │ http://localhost:8080/callback)
                                │                     │
                                │                     │ /authorize?…&code_challenge=…
                                │                     │ ──────────────────────────────►
   open browser ◄────────────── │ ◄───────────────────│
   to upstream                  │                     │
   /authorize URL               │                     │
        │                       │                     │
        │ user logs in          │                     │                                       
        │ ─────────────────────────────────────────────────►
        │                       │                     │                                       
        │ ◄─ redirect to localhost:8080/callback?code=UPSTREAM_CODE
        │                       │                     │
        │                       │                     │ captures UPSTREAM_CODE from
        │                       │                     │ its own localhost listener
        │                       │                     │
        │                       │                     │ /token (PKCE — no client_secret
        │                       │                     │  if public client; client_secret
        │                       │                     │  if confidential)
        │                       │                     │ ──────────────────────────────►
        │                       │                     │ ◄── access_token + refresh_token
        │                       │                     │
        │                       │                     │ persists tokens to
        │                       │                     │ ~/.cache/authsome-mcp-proxy-<ver>/
        │                       │                     │
                                │                     │ tools/prompts/resources
                                │                     │ ───────────────────────────────────────────►
                                │                     │   Authorization: Bearer <upstream JWT>
                                │ ◄─── result ────────│ ◄───────────────────────────────────────────
```

After first successful login the browser dance only repeats when the
refresh token expires; ordinary token rotation happens silently via
`grant_type=refresh_token` against the upstream IdP.

### Detailed step-by-step

| # | Event | Where it happens | Persistent record |
|---|---|---|---|
| 1 | MCP client launches the proxy as a stdio subprocess | Local machine | Proxy reads `OIDC_*` env vars into memory. Nothing on disk yet. |
| 2 | First MCP method invocation (tools/list, etc.) arrives over stdio | Proxy ↔ MCP client | None |
| 3 | Proxy needs to call the upstream MCP server; checks `~/.cache/authsome-mcp-proxy-<version>/` for a cached token | Proxy's local user home | Reads the cache if present and not expired. |
| 4a | No valid cached token: proxy starts an HTTP listener on `OIDC_REDIRECT_URL` (e.g. `http://localhost:8080/callback`) and constructs the upstream `/authorize` URL (`response_type=code`, `code_challenge`, PKCE, requested scopes) | Local | None — PKCE verifier held in memory |
| 4b | Proxy opens the user's default browser to the upstream `/authorize` URL | Local | None |
| 4c | User logs in at the upstream IdP in the browser | Browser ↔ upstream IdP | Upstream issues an auth code, redirects browser back to `http://localhost:8080/callback?code=UPSTREAM_CODE` |
| 4d | Proxy's local listener captures `UPSTREAM_CODE` | Local | None |
| 4e | Proxy calls upstream `/token` server-to-server with `code`, PKCE `code_verifier`, and the proxy's `client_id` (+ `client_secret` if confidential) | Proxy ↔ upstream IdP | Receives `access_token` + `refresh_token`; **writes them to `~/.cache/authsome-mcp-proxy-<version>/`** |
| 5 | Proxy attaches `Authorization: Bearer <access_token>` and forwards the MCP call to the upstream MCP server | Proxy ↔ upstream MCP | None |
| 6 | Subsequent MCP calls reuse the cached access token. When it expires, proxy silently runs `grant_type=refresh_token` against the upstream IdP and updates the cache. | Proxy ↔ upstream IdP | Updated tokens written to the same cache file. |
| 7 | If the refresh token also expires (or is revoked), proxy falls back to the browser flow (steps 4a–4e) on the next outbound call. | Local | Cache overwritten with fresh tokens. |

### Where the cache lives

The proxy stores upstream-IdP tokens locally for the user who owns the
process:

```
${XDG_CACHE_HOME:-$HOME/.cache}/authsome-mcp-proxy-<version>/
```

On Windows this resolves under `%LOCALAPPDATA%` or `%USERPROFILE%\.cache\`
depending on environment. The directory is namespaced by package version
so a re-install doesn't accidentally reuse incompatible cached state.

This cache has nothing to do with the web-mode `${FASTMCP_HOME}/oauth-proxy/`
directory — desktop mode never runs the DCR-bridge code path.

### Reconciling with classical (non-proxied) OAuth intuitions

| Classical OAuth concept | Where it lives here |
|---|---|
| OAuth client | **The proxy.** Single client to the upstream IdP. |
| `client_id` / `client_secret` | In the proxy's env vars (`OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET`) — the user pre-registers a client with the upstream IdP and supplies the credentials to the proxy. |
| `/callback` endpoint | **The proxy's localhost listener** at `OIDC_REDIRECT_URL` (default `http://localhost:8080/callback`). The MCP client has no callback — it doesn't speak OAuth. |
| Authorization code | A single `UPSTREAM_CODE` from the upstream IdP, consumed once in step 4e. No `PROXY_CODE` exists in desktop mode. |
| Token storage | On the user's filesystem (`~/.cache/authsome-mcp-proxy-<version>/`). |

### Persistence and failure modes

- **Token cache lost / first run** → next outbound call triggers the
  browser flow. No data loss; the user just sees a browser popup.
- **Refresh token expired or revoked** → same recovery: browser flow on
  the next outbound call.
- **`OIDC_REDIRECT_URL` port in use** → flow fails to capture the
  callback. Set a different port via `--oidc-redirect-url
  http://localhost:<other-port>/callback` (and make sure the same URL
  is whitelisted in the upstream IdP's app-client config).
- **`OIDC_REDIRECT_URL` mismatch with the upstream IdP's whitelisted
  callbacks** → upstream rejects the `/authorize` request before
  redirecting back. This is the most common misconfiguration in desktop
  mode.

No equivalent of the web-mode PVC question exists here — there is no
shared server state to lose. Each user's tokens live in their own home
directory; pod restarts and Kubernetes are not part of this picture.
