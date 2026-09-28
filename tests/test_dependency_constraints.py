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

    def test_mcp_2_is_excluded(self):
        """mcp 2.x renamed ``McpError`` to ``MCPError``.

        ``authsome_mcp_proxy.__main__`` imports the 1.x spelling at module
        level, so resolving mcp 2.x turns every entry point into an
        ``ImportError`` before the process can speak MCP over stdio.
        """
        specifier = _constraint("mcp").specifier
        assert not specifier.contains("2.0.0")
        assert not specifier.contains("2.1.1")

    def test_fastmcp_4_is_excluded(self):
        """fastmcp 4.x moved its HTTP stack from ``httpx`` to ``httpx2``.

        It requires mcp 2.x, and the outbound auth classes in this package are
        ``httpx.Auth`` subclasses handed to a fastmcp ``Client`` -- a different
        class hierarchy from the one fastmcp 4 passes them to. Leaving fastmcp
        uncapped is what let mcp 2.x in despite the mcp cap being delegated to
        fastmcp.
        """
        specifier = _constraint("fastmcp").specifier
        assert not specifier.contains("4.0.0")
        assert not specifier.contains("4.0.3")
