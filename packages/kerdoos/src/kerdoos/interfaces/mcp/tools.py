"""MCP tools. Each tool resolves its caller through current_principal()."""

from __future__ import annotations

from mcp.server import MCPServer

from kerdoos.interfaces.mcp.auth import current_principal


def register_tools(mcp: MCPServer) -> None:
    @mcp.tool(
        name="whoami",
        description="Return the role of the authenticated caller.")
    def whoami() -> dict[str, str]:
        return {"role": current_principal().role}
