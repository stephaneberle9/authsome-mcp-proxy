# CLAUDE.md

`authsome-mcp-proxy` is a public, Apache-2.0-licensed open-source project.
Everything committed here — code, comments, docstrings, tests, docs,
examples, Dockerfiles, CI workflows, commit messages and PR descriptions — is
published to the world.

## No proprietary references

Never put references to proprietary material into this repository. That
covers anything belonging to the maintainers' employers, customers or other
non-public projects:

- product, project, team or codename names of commercial or internal
  offerings (including in display-name examples, fixture values and test
  server names);
- company-specific hostnames, domains, URLs, tenant/user-pool/account IDs,
  ARNs, cluster or namespace names;
- internal issue trackers, repositories, merge requests, wikis, chat
  channels, meeting decisions or people who are not public contributors;
- deployment details of a specific non-public installation ("the X
  deployment uses …", "in front of X / Y").

Use neutral placeholders instead:

| Kind | Use |
| --- | --- |
| Product / server name | `Acme Analytics`, `acme-repository-mcp`, `upstream-mcp` |
| Domains and URLs | `example.com` / `.org` / `.net` (RFC 2606), `auth.company.com`, `mcp-upstream.company.com` |
| Cloud IDs | obviously fake values such as `eu-central-1_XXXXXXXXX`, `eu-central-1_abc`, `tid` |
| Deployment context | generic wording: "a production deployment", "token-validating upstream MCP servers" |

Public third-party services and standards (Cognito, Keycloak, Azure, Google,
GitHub, GitLab, Personio, Lexware, CoinDesk, RFCs, the MCP SDK and FastMCP
issue numbers) are fine to name.

Before finishing any change, check the diff for names, hosts or IDs that
come from a non-public context and replace them. When in doubt, use a
placeholder. A commit or PR that removes such a reference describes the
change generically ("use neutral placeholder names") and never quotes or
names what was removed, nor points at the earlier commits that introduced
it.

Maintainer working files (`.triage/`) are local only and git-ignored; never
copy their content into tracked files, commits or PRs.
