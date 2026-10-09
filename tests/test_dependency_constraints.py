"""Tests for the dependency constraints this package publishes.

``uv.lock`` is a development artifact: it is excluded from wheels and ignored
by ``uvx``/``pip``, so what end users actually resolve against is the
``dependencies`` metadata built from ``pyproject.toml`` (see CONTRIBUTING,
"Dependency Management and Lock Files"). A locked CI run therefore proves
nothing about a fresh ``uvx authsome-mcp-proxy``, and the checks below assert
the published metadata rather than the installed versions.
"""

from importlib.metadata import requires

from packaging.requirements import Requirement


def _constraint(distribution: str) -> Requirement:
    """Return the published requirement on ``distribution``."""
    declared = requires("authsome-mcp-proxy") or []
    for entry in declared:
        requirement = Requirement(entry)
        if requirement.name == distribution:
            return requirement
    raise AssertionError(f"{distribution} is not a declared dependency")


class TestPublishedDependencyConstraints:
    """Majors this code cannot run on must be unresolvable for end users."""

    def test_mcp_1_is_excluded(self):
        """mcp 2.0 renamed ``McpError`` to ``MCPError``.

        ``authsome_mcp_proxy.__main__`` imports the 2.x spelling at module
        level, so resolving mcp 1.x turns every entry point into an
        ``ImportError`` before the process can speak MCP over stdio.
        """
        specifier = _constraint("mcp").specifier
        assert not specifier.contains("1.27.1")
        assert specifier.contains("2.0.0")

    def test_fastmcp_3_is_excluded(self):
        """fastmcp 4 moved its HTTP stack from ``httpx`` to ``httpx2``.

        The outbound auth classes in this package are ``httpx2.Auth``
        subclasses handed to a fastmcp ``Client``. fastmcp 3 builds an
        ``httpx`` client, which rejects them with ``TypeError: Invalid "auth"
        argument`` when the upstream connection opens -- not at import, so no
        import smoke test would notice.
        """
        specifier = _constraint("fastmcp").specifier
        assert not specifier.contains("3.4.7")
        assert specifier.contains("4.0.8")

    def test_fastmcp_before_4_0_8_is_excluded(self):
        """4.0.8 is the first release with all the OAuthProxy security fixes.

        4.0.4 rejects ID-JAG tokens unless identity assertion is configured,
        4.0.6 keeps Google access tokens out of request URLs, and 4.0.8 revokes
        the upstream refresh token instead of sending the proxy's own token
        upstream.
        """
        specifier = _constraint("fastmcp").specifier
        assert not specifier.contains("4.0.7")

    def test_fastmcp_5_is_excluded(self):
        """Web mode depends on fastmcp's private ``_lifespan_manager``.

        One FastMCP server backs an ASGI app per public hostname, and the
        server's lifespan is shared between them only because
        ``_lifespan_manager`` is reference-counted. A private method carries no
        compatibility promise, and ``uvx`` resolves the newest fastmcp at
        install time, so a major that renames it or drops the counting must be
        unresolvable rather than break web mode at startup -- or, worse, run
        the server lifespan once per hostname.
        """
        specifier = _constraint("fastmcp").specifier
        assert not specifier.contains("5.0.0")
        assert specifier.contains("4.1.0")

    def test_legacy_httpx_is_not_declared(self):
        """Nothing here imports ``httpx`` any more; ``httpx2`` replaces it."""
        declared = {Requirement(r).name for r in requires("authsome-mcp-proxy") or []}
        assert "httpx" not in declared
        assert "httpx2" in declared
